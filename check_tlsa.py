#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_dane_smtp.py
===================

Script destiné à être lancé par crontab. Il effectue, pour un ou plusieurs
serveurs SMTP :

  1. La vérification STRICTE de l'enregistrement DNS DANE (TLSA) associé au
     serveur (_<port>._tcp.<hostname>), c'est-à-dire la correspondance entre
     le contenu de l'enregistrement TLSA et le bon certificat de la chaîne
     réellement présentée par le serveur, en tenant compte du champ "usage" :
       - usage 1 (PKIX-EE) et 3 (DANE-EE) : correspondance attendue avec le
         certificat final (leaf) du serveur.
       - usage 0 (PKIX-TA) et 2 (DANE-TA) : correspondance attendue avec un
         certificat d'autorité (CA) présent dans la chaîne envoyée par le
         serveur (intermédiaire ou racine), pas avec le certificat final.
     La chaîne complète est récupérée via pyOpenSSL (get_peer_cert_chain),
     ce qu'une simple connexion ssl.SSLSocket ne permet pas.
  2. La récupération de la date d'expiration du certificat TLS présenté
     (via une connexion SMTP + STARTTLS).
  3. L'envoi d'un e-mail d'alerte si :
       - le certificat expire dans moins de N jours (renouvellement à faire),
       - et/ou l'enregistrement TLSA est absent, invalide, ou ne correspond
         plus au bon certificat de la chaîne selon son usage (donc à mettre
         à jour après renouvellement).

Dépendances (à installer une fois, ou voir requirements.txt fourni) :
    pip3 install -r requirements.txt

Configuration :
    Toute la configuration se fait via le fichier /etc/check_dane_smtp.json
    (ou un autre chemin passé en argument --config), voir la variable
    DEFAULT_CONFIG ci-dessous pour le format attendu.

Exemple crontab (vérification tous les jours à 6h00) :
    0 6 * * *  /usr/bin/python3 /opt/scripts/check_dane_smtp.py \
               --config /etc/check_dane_smtp.json >> /var/log/check_dane_smtp.log 2>&1

Codes de sortie :
    0 : tout est OK (avec ou sans rapport quotidien envoyé)
    1 : erreur de configuration / exécution, ou échec d'envoi du rapport quotidien
    2 : alerte envoyée avec succès (certificat proche de l'expiration ou TLSA invalide)
"""

import argparse
import datetime
import hashlib
import json
import logging
import select
import smtplib
import socket
import ssl
import sys
import time
from email.mime.text import MIMEText
from email.header import Header

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("Le module 'dnspython' est requis : pip3 install dnspython", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Le module 'cryptography' est requis : pip3 install cryptography", file=sys.stderr)
    sys.exit(1)

try:
    from OpenSSL import SSL, crypto
except ImportError:
    print("Le module 'pyOpenSSL' est requis (vérification stricte de la chaîne) : pip3 install pyOpenSSL", file=sys.stderr)
    sys.exit(1)

# Usages TLSA définis par la RFC 6698.
TLSA_USAGE_PKIX_TA = 0   # CA ancrage, doit aussi être valide via la PKI publique
TLSA_USAGE_PKIX_EE = 1   # certificat final, doit aussi être valide via la PKI publique
TLSA_USAGE_DANE_TA = 2   # CA ancrage, validation PKI publique non requise
TLSA_USAGE_DANE_EE = 3   # certificat final, validation PKI publique non requise
LEAF_USAGES = (TLSA_USAGE_PKIX_EE, TLSA_USAGE_DANE_EE)
CA_USAGES = (TLSA_USAGE_PKIX_TA, TLSA_USAGE_DANE_TA)


# ---------------------------------------------------------------------------
# Configuration par défaut (utilisée si le fichier de config ne précise pas
# certaines clés). À adapter selon vos besoins.
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # Liste des serveurs SMTP à contrôler.
    "servers": [
        {
            "hostname": "mail.example.com",
            "port": 25,
            # Nombre de jours avant expiration à partir duquel on alerte.
            "alert_days_before_expiry": 15,
        }
    ],
    # Timeout réseau (secondes) pour les connexions DNS et SMTP.
    "network_timeout": 10,
    # Paramètres d'envoi de l'e-mail d'alerte.
    "mail": {
        "smtp_host": "localhost",
        "smtp_port": 25,
        "use_starttls": False,
        "tls_verify": True,
        "username": None,
        "password": None,
        "mail_from": "surveillance-dane@example.com",
        "mail_to": ["admin@example.com"],
        "subject_prefix": "[ALERTE DANE/TLS]",
        "always_send_report": False,
        "report_subject_prefix_ok": "[Rapport DANE/TLS]",
    },
    # Chemin du fichier de log (en plus de la sortie standard).
    "log_file": None,
    "log_level": "INFO",
}


# ---------------------------------------------------------------------------
# Structures de résultat
# ---------------------------------------------------------------------------
class ServerCheckResult:
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.cert_not_after = None          # datetime UTC
        self.days_remaining = None
        self.tlsa_records = []              # liste de dicts {usage, selector, mtype, data}
        self.tlsa_ok = False                # au moins un enregistrement TLSA correspond STRICTEMENT
        self.tlsa_present = False
        self.tlsa_match_details = []        # détail texte de la vérification stricte, par enregistrement
        self.chain_length = 0               # nombre de certificats reçus dans la chaîne du serveur
        self.errors = []                    # erreurs rencontrées (connexion, DNS, etc.)

    @property
    def needs_alert(self, threshold=None):
        raise NotImplementedError  # calcul fait explicitement dans main()


def _describe_exception(exc):
    """
    Renvoie un message d'erreur toujours non vide. Certaines exceptions de
    pyOpenSSL (WantReadError, WantWriteError, parfois Error) ont un str()
    vide ; on retombe alors sur le nom de la classe (+ repr si disponible).
    """
    msg = str(exc).strip()
    if msg:
        return msg
    r = repr(exc)
    return r if r and r != "%s()" % type(exc).__name__ else type(exc).__name__


def _ssl_do_handshake_with_retry(conn, sock, timeout):
    """
    Effectue le handshake TLS pyOpenSSL en gérant correctement les
    WantReadError/WantWriteError : même sur un socket "bloquant", OpenSSL
    peut demander de relire quand plus de données réseau sont nécessaires.
    Sans cette boucle, do_handshake() peut échouer avec une exception dont
    le message est vide, ce qui est trompeur.
    """
    deadline = None
    if timeout is not None:
        deadline = time.time() + timeout

    while True:
        try:
            conn.do_handshake()
            return
        except SSL.WantReadError:
            remaining = None
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(
                        "Délai dépassé pendant le handshake TLS (WantReadError)."
                    )
            readable, _, _ = select.select([sock], [], [], remaining)
            if not readable and deadline is not None:
                raise TimeoutError(
                    "Délai dépassé pendant le handshake TLS (WantReadError)."
                )
        except SSL.WantWriteError:
            remaining = None
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(
                        "Délai dépassé pendant le handshake TLS (WantWriteError)."
                    )
            _, writable, _ = select.select([], [sock], [], remaining)
            if not writable and deadline is not None:
                raise TimeoutError(
                    "Délai dépassé pendant le handshake TLS (WantWriteError)."
                )


# ---------------------------------------------------------------------------
# Récupération de la chaîne de certificats présentée par le serveur SMTP
# (via STARTTLS), nécessaire pour la vérification stricte de l'usage TLSA.
# ---------------------------------------------------------------------------
def _read_smtp_line(sock_file):
    line = sock_file.readline()
    if not line:
        raise RuntimeError("Connexion fermée de manière inattendue par le serveur SMTP.")
    return line.decode("ascii", errors="replace").rstrip("\r\n")


def _read_smtp_response(sock_file):
    """Lit une réponse SMTP potentiellement multi-lignes (ex: 250-... 250 ...)."""
    code = None
    lines = []
    while True:
        line = _read_smtp_line(sock_file)
        lines.append(line)
        code = line[:3]
        if len(line) >= 4 and line[3] == " ":
            break
        if len(line) == 3:
            break
    return code, lines


def get_smtp_certificate_chain(hostname, port, timeout=10):
    """
    Négocie manuellement EHLO/STARTTLS en clair, puis bascule la connexion en
    TLS via pyOpenSSL afin de pouvoir récupérer la CHAÎNE COMPLÈTE de
    certificats (get_peer_cert_chain), indispensable pour vérifier
    correctement les enregistrements TLSA d'usage 0/2 (ancrage CA) et pas
    seulement le certificat final.

    Retourne une liste de tuples (x509.Certificate cryptography, bytes DER),
    le premier élément étant le certificat final (leaf) du serveur.
    """
    raw_sock = socket.create_connection((hostname, port), timeout=timeout)
    raw_sock.settimeout(timeout)
    sock_file = raw_sock.makefile("rb")

    try:
        # Bannière de connexion (220 ...)
        code, _ = _read_smtp_response(sock_file)
        if code != "220":
            raise RuntimeError("Bannière SMTP inattendue de %s:%s (%s)" % (hostname, port, code))

        raw_sock.sendall(b"EHLO check-dane-smtp\r\n")
        code, lines = _read_smtp_response(sock_file)
        if code != "250":
            raise RuntimeError("EHLO refusé par %s:%s (%s)" % (hostname, port, code))

        if not any("STARTTLS" in l.upper() for l in lines):
            raise RuntimeError("Le serveur %s:%s n'annonce pas l'extension STARTTLS." % (hostname, port))

        raw_sock.sendall(b"STARTTLS\r\n")
        code, _ = _read_smtp_response(sock_file)
        if code != "220":
            raise RuntimeError("STARTTLS refusé par %s:%s (%s)" % (hostname, port, code))

        # Bascule TLS avec pyOpenSSL pour accéder à la chaîne complète.
        ctx = SSL.Context(SSL.TLS_METHOD)
        # On ne valide pas la chaîne de confiance classique ici : l'objectif
        # est justement de contrôler DANE indépendamment de la PKI publique.
        ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)

        conn = SSL.Connection(ctx, raw_sock)
        conn.set_connect_state()
        try:
            conn.set_tlsext_host_name(hostname.encode("ascii"))
        except Exception:
            pass  # SNI non critique pour ce contrôle
        # Le socket reste bloquant (nécessaire pour select() dans la boucle
        # de handshake ci-dessous) ; le timeout global est appliqué "à la
        # main" via la deadline passée à _ssl_do_handshake_with_retry.
        raw_sock.setblocking(True)
        _ssl_do_handshake_with_retry(conn, raw_sock, timeout)

        chain = conn.get_peer_cert_chain()
        if not chain:
            raise RuntimeError("Impossible de récupérer la chaîne de certificats de %s:%s" % (hostname, port))

        result = []
        for ossl_cert in chain:
            der = crypto.dump_certificate(crypto.FILETYPE_ASN1, ossl_cert)
            cert = x509.load_der_x509_certificate(der, default_backend())
            result.append((cert, der))

        try:
            conn.shutdown()
        except Exception:
            pass

        return result
    finally:
        try:
            sock_file.close()
        except Exception:
            pass
        try:
            raw_sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Interrogation DNS de l'enregistrement TLSA (DANE)
# ---------------------------------------------------------------------------
def get_tlsa_records(hostname, port, timeout=10):
    """
    Interroge l'enregistrement TLSA _<port>._tcp.<hostname> et renvoie une
    liste de dicts {usage, selector, mtype, data (bytes)}.
    """
    qname = "_%d._tcp.%s" % (port, hostname.rstrip("."))
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records = []
    try:
        answer = resolver.resolve(qname, "TLSA")
        for rdata in answer:
            records.append(
                {
                    "usage": rdata.usage,
                    "selector": rdata.selector,
                    "mtype": rdata.mtype,
                    "data": rdata.cert,  # bytes
                }
            )
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException as exc:
        raise RuntimeError("Erreur DNS lors de la lecture de %s (TLSA) : %s" % (qname, exc))

    return records


def _certificate_matches_data(cert, der_cert, selector, mtype, expected):
    """
    Compare un certificat donné aux données d'un enregistrement TLSA, selon
    le sélecteur (0=certificat complet, 1=SubjectPublicKeyInfo) et le type de
    correspondance (0=exact, 1=SHA-256, 2=SHA-512).
    """
    if selector == 0:
        subject = der_cert
    elif selector == 1:
        subject = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        return False  # sélecteur inconnu (RFC 6698 : seuls 0 et 1 existent)

    if mtype == 0:
        candidate = subject
    elif mtype == 1:
        candidate = hashlib.sha256(subject).digest()
    elif mtype == 2:
        candidate = hashlib.sha512(subject).digest()
    else:
        return False  # type de correspondance inconnu

    return candidate == expected


def tlsa_record_matches_chain(record, chain):
    """
    Vérification STRICTE d'un enregistrement TLSA par rapport à la chaîne de
    certificats présentée par le serveur, en respectant le champ "usage"
    (RFC 6698 §2.1.1) :

      - usage 1 (PKIX-EE) / 3 (DANE-EE) : la correspondance DOIT se faire
        avec le certificat final (leaf), chain[0]. Une correspondance avec un
        certificat intermédiaire ou racine est ignorée (non conforme).
      - usage 0 (PKIX-TA) / 2 (DANE-TA) : la correspondance DOIT se faire
        avec un certificat d'autorité de la chaîne (chain[1:], intermédiaires
        et/ou racine). Une correspondance avec le certificat final seul ne
        compte pas.

    Retourne un tuple (match: bool, detail: str).
    """
    usage = record["usage"]
    selector = record["selector"]
    mtype = record["mtype"]
    expected = record["data"]

    if usage in LEAF_USAGES:
        if not chain:
            return False, "chaîne vide"
        cert, der = chain[0]
        ok = _certificate_matches_data(cert, der, selector, mtype, expected)
        return ok, "comparé au certificat final (usage=%d)" % usage

    if usage in CA_USAGES:
        ca_certs = chain[1:]
        if not ca_certs:
            return False, (
                "usage=%d (ancrage CA) mais le serveur n'a présenté aucun "
                "certificat intermédiaire/racine à comparer" % usage
            )
        for cert, der in ca_certs:
            if _certificate_matches_data(cert, der, selector, mtype, expected):
                return True, "comparé à un certificat CA de la chaîne (usage=%d)" % usage
        return False, "comparé aux certificats CA de la chaîne (usage=%d), aucune correspondance" % usage

    return False, "usage TLSA inconnu (%r)" % usage


# ---------------------------------------------------------------------------
# Contrôle complet d'un serveur
# ---------------------------------------------------------------------------
def check_server(hostname, port, timeout=10):
    result = ServerCheckResult(hostname, port)

    # 1. Chaîne de certificats présentée par le serveur
    try:
        chain = get_smtp_certificate_chain(hostname, port, timeout=timeout)
        result.chain_length = len(chain)
        leaf_cert, _ = chain[0]
        not_after = (
            leaf_cert.not_valid_after_utc
            if hasattr(leaf_cert, "not_valid_after_utc")
            else leaf_cert.not_valid_after
        )
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        result.cert_not_after = not_after
        now = datetime.datetime.now(datetime.timezone.utc)
        result.days_remaining = (not_after - now).days
    except Exception as exc:
        result.errors.append("Certificat : %s" % _describe_exception(exc))
        return result  # inutile de continuer sans certificat/chaîne

    # 2. Enregistrement(s) TLSA, vérification STRICTE (tient compte de l'usage)
    try:
        records = get_tlsa_records(hostname, port, timeout=timeout)
        result.tlsa_records = records
        result.tlsa_present = len(records) > 0
        if not result.tlsa_present:
            result.errors.append("Aucun enregistrement TLSA trouvé pour _%d._tcp.%s" % (port, hostname))
        else:
            match_details = []
            any_match = False
            for r in records:
                ok, detail = tlsa_record_matches_chain(r, chain)
                match_details.append(
                    "usage=%d selector=%d mtype=%d -> %s (%s)"
                    % (r["usage"], r["selector"], r["mtype"], "OK" if ok else "NON", detail)
                )
                any_match = any_match or ok
            result.tlsa_ok = any_match
            result.tlsa_match_details = match_details
            if not result.tlsa_ok:
                result.errors.append(
                    "Aucun enregistrement TLSA ne correspond STRICTEMENT (selon son usage) à la "
                    "chaîne de certificats présentée (mise à jour de l'enregistrement DANE "
                    "probablement nécessaire)."
                )
    except Exception as exc:
        result.errors.append("TLSA : %s" % _describe_exception(exc))

    return result


# ---------------------------------------------------------------------------
# Envoi de l'e-mail d'alerte
# ---------------------------------------------------------------------------
def _build_client_ssl_context(mail_cfg):
    """
    Contexte TLS utilisé pour le STARTTLS vers le relais d'envoi des alertes.
    Par défaut, vérification stricte (CA système + nom d'hôte). Si le relais
    utilise un certificat auto-signé/interne, mettre "tls_verify": false
    dans la config (mail.tls_verify).
    """
    if mail_cfg.get("tls_verify", True):
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_alert_email(mail_cfg, subject, body):
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = mail_cfg["mail_from"]
    msg["To"] = ", ".join(mail_cfg["mail_to"])

    smtp = smtplib.SMTP(mail_cfg["smtp_host"], mail_cfg["smtp_port"], timeout=15)
    try:
        smtp.ehlo()
        if mail_cfg.get("use_starttls"):
            ctx = _build_client_ssl_context(mail_cfg)
            smtp.starttls(context=ctx)
            # smtplib réinitialise les extensions annoncées après STARTTLS
            # (certains serveurs n'annoncent AUTH qu'après le passage en TLS) ;
            # on relance donc explicitement un EHLO pour les redécouvrir.
            smtp.ehlo()
        if mail_cfg.get("username") and mail_cfg.get("password"):
            if not smtp.has_extn("auth"):
                raise RuntimeError(
                    "Le serveur %s:%s n'annonce pas l'extension AUTH sur cette connexion "
                    "(essayez le port 587, ou videz username/password si l'authentification "
                    "n'est pas requise pour ce relais)." % (mail_cfg["smtp_host"], mail_cfg["smtp_port"])
                )
            smtp.login(mail_cfg["username"], mail_cfg["password"])
        smtp.sendmail(mail_cfg["mail_from"], mail_cfg["mail_to"], msg.as_string())
    finally:
        smtp.quit()


def build_report_text(result, alert_days_before_expiry):
    lines = []
    lines.append("Serveur SMTP : %s:%s" % (result.hostname, result.port))
    lines.append("Date de contrôle : %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")

    if result.cert_not_after:
        lines.append("Date d'expiration du certificat : %s (UTC)" % result.cert_not_after.strftime("%Y-%m-%d %H:%M:%S"))
        lines.append("Jours restants avant expiration  : %s" % result.days_remaining)
        lines.append("Seuil d'alerte configuré         : %s jours" % alert_days_before_expiry)
    else:
        lines.append("Impossible de récupérer le certificat du serveur.")

    lines.append("")
    lines.append("Longueur de la chaîne de certificats reçue : %d" % result.chain_length)
    lines.append("Enregistrement(s) TLSA (DANE) trouvé(s) : %d" % len(result.tlsa_records))
    if result.tlsa_match_details:
        for detail in result.tlsa_match_details:
            lines.append("  - %s" % detail)
    lines.append("Correspondance TLSA stricte (usage inclus) : %s" % ("OK" if result.tlsa_ok else "NON"))

    if result.errors:
        lines.append("")
        lines.append("Anomalies détectées :")
        for err in result.errors:
            lines.append("  - %s" % err)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chargement de la configuration
# ---------------------------------------------------------------------------
def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        user_cfg = json.load(f)

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # copie profonde
    cfg.update({k: v for k, v in user_cfg.items() if k != "mail"})
    if "mail" in user_cfg:
        cfg["mail"].update(user_cfg["mail"])
    if "servers" in user_cfg:
        cfg["servers"] = user_cfg["servers"]
    return cfg


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Contrôle DANE (TLSA) et expiration de certificat pour serveur(s) SMTP, "
                    "avec alerte par e-mail. Prévu pour être lancé via crontab."
    )
    parser.add_argument(
        "--config",
        default="/etc/check_dane_smtp.json",
        help="Chemin du fichier de configuration JSON (défaut : /etc/check_dane_smtp.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="N'envoie pas d'e-mail, affiche seulement le résultat des contrôles.",
    )
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print("Erreur de chargement de la configuration '%s' : %s" % (args.config, exc), file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        level=getattr(logging, cfg.get("log_level", "INFO"), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=(
            [logging.FileHandler(cfg["log_file"]), logging.StreamHandler()]
            if cfg.get("log_file")
            else [logging.StreamHandler()]
        ),
    )
    log = logging.getLogger("check_dane_smtp")

    timeout = cfg.get("network_timeout", 10)
    alerts_to_send = []
    all_results = []  # (hostname, port, result, threshold) — tous les serveurs, OK compris

    for server_cfg in cfg["servers"]:
        hostname = server_cfg["hostname"]
        port = server_cfg.get("port", 25)
        threshold = server_cfg.get("alert_days_before_expiry", 15)

        log.info("Contrôle de %s:%s ...", hostname, port)
        result = check_server(hostname, port, timeout=timeout)
        all_results.append((hostname, port, result, threshold))

        expiry_alert = (
            result.days_remaining is not None and result.days_remaining <= threshold
        )
        tlsa_alert = not result.tlsa_present or not result.tlsa_ok
        has_hard_error = result.cert_not_after is None

        if expiry_alert or tlsa_alert or has_hard_error:
            report = build_report_text(result, threshold)
            log.warning("Anomalie détectée pour %s:%s\n%s", hostname, port, report)

            if expiry_alert and result.days_remaining is not None:
                subject_detail = "expiration certificat dans %d jour(s)" % result.days_remaining
            elif has_hard_error:
                subject_detail = "erreur de contrôle"
            else:
                subject_detail = "enregistrement TLSA à vérifier"

            subject = "%s %s (%s)" % (
                cfg["mail"]["subject_prefix"],
                hostname,
                subject_detail,
            )
            alerts_to_send.append((subject, report))
        else:
            log.info(
                "%s:%s OK — certificat valide encore %d jour(s), TLSA conforme.",
                hostname,
                port,
                result.days_remaining,
            )

    if not alerts_to_send:
        if not cfg["mail"].get("always_send_report"):
            log.info("Aucune alerte à envoyer.")
            sys.exit(0)

        # Option "rapport quotidien" activée : tout est OK, mais on envoie
        # quand même un e-mail récapitulatif de contrôle.
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        subject = "%s %s — %d serveur(s) OK" % (
            cfg["mail"].get("report_subject_prefix_ok", "[Rapport DANE/TLS]"),
            today,
            len(all_results),
        )
        body_parts = [
            "Rapport de contrôle DANE/TLS du %s — aucune anomalie détectée sur %d serveur(s)."
            % (today, len(all_results)),
            "",
        ]
        for hostname, port, result, threshold in all_results:
            body_parts.append(build_report_text(result, threshold))
            body_parts.append("-" * 70)
        body = "\n".join(body_parts)

        if args.dry_run:
            log.info("--dry-run actif : rapport quotidien (tout OK) non envoyé.")
            sys.exit(0)

        try:
            send_alert_email(cfg["mail"], subject, body)
            log.info("Rapport quotidien envoyé : %s", subject)
        except Exception as exc:
            log.error("Échec de l'envoi du rapport quotidien : %s", _describe_exception(exc))
            sys.exit(1)

        sys.exit(0)

    if args.dry_run:
        log.info("--dry-run actif : %d alerte(s) détectée(s), aucun e-mail envoyé.", len(alerts_to_send))
        sys.exit(2)

    for subject, body in alerts_to_send:
        try:
            send_alert_email(cfg["mail"], subject, body)
            log.info("E-mail d'alerte envoyé : %s", subject)
        except Exception as exc:
            log.error("Échec de l'envoi de l'e-mail d'alerte '%s' : %s", subject, _describe_exception(exc))

    sys.exit(2)


if __name__ == "__main__":
    main()

