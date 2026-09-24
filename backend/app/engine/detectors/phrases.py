"""Phrase-level detector: finds manipulation tactics in English, French and Kreol Morisien.

Each rule is a regular expression tagged with a tactic. Matches keep their
character offsets so the app can highlight the exact words ("Scam X-Ray").

NOTE: the Kreol Morisien phrases are a starting set. Have a native speaker
review and extend them; spelling varies a lot in SMS.
"""
import re
from dataclasses import dataclass

from .base import DetectionContext, Signal

FLAGS = re.IGNORECASE | re.UNICODE


@dataclass(frozen=True)
class Rule:
    tactic: str
    pattern: re.Pattern
    weight: float | None = None
    detail: str | None = None
    negatable: bool = False   # skip the match if it follows "never", "do not", ...


def _r(tactic: str, pattern: str, weight: float | None = None, detail: str | None = None,
       negatable: bool = False) -> Rule:
    return Rule(tactic, re.compile(pattern, FLAGS), weight, detail, negatable)


_CRED_VERBS = (r"(?:reply(?:ing)? with|send|share|give|provide|enter|confirm|verify|update|tell us|forward|"
               r"type|submit|input|read out)")
_CRED_OBJECTS = (r"(?:otp|one[- ]time (?:password|code|pin)|pin(?: code| number)?|password|passcode|cvv|cvc|"
                 r"card (?:number|details)|security code|verification code|login details|"
                 r"(?:bank(?:ing)?|account|card) details|credentials)")
_FR_CRED_VERBS = (r"(?:confirmer|confirmez|envoyer|envoyez|communiquer|communiquez|saisir|saisissez|donner|"
                  r"donnez|indiquer|indiquez|mettre à jour|valider|validez)")
_FR_CRED_OBJECTS = (r"(?:code (?:otp|de v[ée]rification|secret|pin|de s[ée]curit[ée])|otp|mot de passe|"
                    r"coordonn[ée]es bancaires|num[ée]ro de carte|cvv|code pin|identifiants)")
_MONEY = r"(?:rs\.?|mur|rupees?|roupies?|roupi|€|\$|usd|eur|usdt|money|fee|fees|amount|payment|cash|kas|larzan)"

RULES: list[Rule] = [
    # ---- Urgency ----------------------------------------------------------
    _r("urgency", r"\bwithin \d+\s*(?:hours?|hrs?|h|minutes?|mins?|days?)\b"),
    _r("urgency", r"\b(?:act|respond|reply|pay|verify|confirm|transfer|send|click)\b[^.!?\n]{0,40}?"
                  r"\b(?:now|immediately|today|tonight|right away)\b"),
    _r("urgency", r"\burgent(?:ly)?\b"),
    _r("urgency", r"\bimmediately\b"),
    _r("urgency", r"\b(?:today only|last chance|final (?:notice|warning|reminder)|asap|as soon as possible)\b"),
    _r("urgency", r"\b(?:offer |deal )?ends? (?:tonight|today|soon|in \d+)\b"),
    _r("urgency", r"\blimited (?:time|slots?|offer|places|spots)\b"),
    _r("urgency", r"\bexpires? (?:today|tonight|in \d+)"),
    _r("urgency", r"\b(?:imm[ée]diatement|d[èe]s maintenant|dernier d[ée]lai|au plus vite)\b"),
    _r("urgency", r"\b(?:sous|d'ici|dans les) \d+\s*(?:heures|h|minutes)\b"),
    _r("urgency", r"\baujourd['’]hui\b", weight=0.15),
    _r("urgency", r"\b(?:vit vit|zordi mem|aster mem|aster la)\b"),
    _r("urgency", r"\b(?:urzan|depese|dan (?:\d+|enn|de) (?:minit|ler)|avan (?:aswar|minwi|dimin))\b"),

    # ---- Authority / impersonating an organisation ------------------------
    _r("authority", r"\b(?:dear|valued) (?:customer|client|user|member|account holder)\b",
       detail="Generic greeting: your real bank normally uses your name."),
    _r("authority", r"\bch[èe]re? client(?:e)?\b",
       detail="Generic greeting: your real bank normally uses your name."),
    _r("authority", r"\b(?:security|fraud|verification|compliance|billing) (?:department|team|unit|centre|center)\b"),
    _r("authority", r"\b(?:customer (?:care|service|support)|service client(?:s|èle)?)\b", weight=0.1),
    _r("authority", r"\b(?:customs|douane|police|court|tribunal|interpol)\b", weight=0.2),

    # ---- Threats / fear -----------------------------------------------------
    _r("threat", r"\b(?:account|card|access|profile|number)\b[^.!?\n]{0,35}?\b(?:suspended|blocked|locked|"
                 r"closed|deactivated|frozen|terminated|restricted|disabled)\b"),
    _r("threat", r"\b(?:will be|has been|have been|is being)\s+(?:temporarily\s+)?(?:suspended|blocked|locked|"
                 r"closed|deactivated|frozen|terminated|cancell?ed)\b"),
    _r("threat", r"\bpermanent(?:ly)? (?:closure|closed|suspension|suspended|blocked|deleted)\b"),
    _r("threat", r"\b(?:legal action|arrest(?:ed)?|warrant|prosecut\w+|penalt(?:y|ies))\b"),
    _r("threat", r"\breturned to sender\b|\bwill be (?:destroyed|disposed)\b", weight=0.2),
    _r("threat", r"\bunusual (?:activity|login|sign-in|transaction)\b", weight=0.2),
    _r("threat", r"\b(?:sera|seront|a [ée]t[ée]|est|va [êe]tre)\s+(?:temporairement\s+)?(?:bloqu[ée]e?s?|"
                 r"suspendue?s?|d[ée]sactiv[ée]e?s?|ferm[ée]e?s?)\b"),
    _r("threat", r"\b(?:poursuites?|amende|p[ée]nalit[ée])\b"),
    _r("threat", r"\b(?:pou (?:bloke|ferm)|finn bloke|pou gagn problem)\b"),
    _r("threat", r"\b(?:kart|kont|konte)(?: labank)?\s+(?:finn|pou|inn|pe)\s+(?:bloke|expire|ferme|ferm|sispann|kanse)\b"),

    # ---- Secrecy -----------------------------------------------------------
    _r("secrecy", r"\b(?:don'?t|do not|dont|please don'?t)\s+(?:tell|inform|call|contact)\s+(?:anyone|anybody|"
                  r"your (?:family|bank|husband|wife|children|kids|parents)|dad|mum|mom|mother|father|him|her|"
                  r"the bank)\b"),
    _r("secrecy", r"\b(?:don'?t|do not)\s+(?:discuss|share|mention)\s+this\b[^.!?\n]{0,20}?\bwith (?:anyone|anybody|"
                  r"your (?:family|bank))\b"),
    _r("secrecy", r"\bkeep (?:this|it) (?:secret|confidential|private|between us|to yourself)\b"),
    _r("secrecy", r"\bbetween (?:you and me|us)\b"),
    _r("secrecy", r"\b(?:ne (?:le )?dites? (?:rien )?[àa] personne|n['’]en parlez [àa] personne|"
                  r"gardez (?:cela|ceci|le) (?:secret|confidentiel))\b"),
    _r("secrecy", r"\b(?:pa dir (?:personn|dimounn|zot|papa|mama)|pa koz sa ar personn)\b"),

    # ---- Too good to be true -------------------------------------------
    _r("reward", r"\bcongratulations?\b", weight=0.2),
    _r("reward", r"\byou(?:'ve| have)? (?:won|been selected|been chosen)\b"),
    _r("reward", r"\b(?:guaranteed|risk[- ]free|zero risk|no risk|100% (?:safe|guaranteed|sure))\b"),
    _r("reward", r"\b(?:double|triple) your (?:money|investment|savings)\b"),
    _r("reward", r"\b\d{1,3}\s?% (?:per|a|every|each) (?:day|week|month)\b",
       detail="Promised returns like this are far above anything a legitimate investment offers."),
    _r("reward", r"\b(?:lottery|jackpot|prize|lucky winner|cash reward|free iphone)\b"),
    _r("reward", r"\bearn (?:rs\.?|mur|\$)?\s?[\d,]+ (?:per|a|every) (?:day|week)\b"),
    _r("reward", r"\b(?:f[ée]licitations|vous avez (?:gagn[ée]|[ée]t[ée] s[ée]lectionn[ée]e?)|sans risque|"
                 r"rendement garanti|gagnant)\b"),
    _r("reward", r"\b(?:ou finn gagn[eé]?|loto|tiraz|kas gratis)\b"),
    _r("reward", r"\b(?:felisitasion|felisitation|ou finn sorti gagnan|enn kado|gagn enn (?:kado|prix)|reponn wi)\b"),

    # ---- Payment request -----------------------------------------------
    _r("payment_request", rf"\b(?:pay|transfer|send|deposit|remit|settle|lend)\b[^.!?\n]{{0,25}}?{_MONEY}(?![a-z])",
       negatable=True),
    _r("payment_request", r"\b(?:release|processing|delivery|customs|clearance|admin(?:istration)?|registration|"
                          r"activation|handling|unlock(?:ing)?|withdrawal|tax) fee\b",
       detail="Small 'fees' are a common hook: once you pay one, more follow."),
    _r("payment_request", r"\bpay (?:a|the) (?:small )?fee\b", negatable=True),
    _r("payment_request", r"\bcan you (?:send|transfer|lend)\b"),
    _r("payment_request", r"\b(?:payez|r[ée]glez|virez|envoyez|transf[ée]rez)\b", negatable=True),
    _r("payment_request", r"\bfrais de (?:livraison|d[ée]douanement|traitement|dossier|lib[ée]ration)\b"),
    _r("payment_request", rf"\bavoy\b[^.!?\n]{{0,25}}?(?:{_MONEY}|kas|larzan)(?![a-z])"),
    _r("payment_request", rf"\b(?:voy|avoy|prete|pret|transfer[eé]?|pey[eé]?)\s+(?:mwa|mw|nou|li)\b[^.!?\n]{{0,30}}?"
                          rf"(?:{_MONEY}|\d)", negatable=True),
    _r("payment_request", r"\b(?:ou kapav|eski ou kapav|to kapav) (?:prete|pret|avoy|voy|transfer)\b"),

    # ---- Credential request (strongest signal) ---------------------------
    _r("credential_request", rf"\b{_CRED_VERBS}\b[^.!?\n]{{0,40}}?\b{_CRED_OBJECTS}\b", negatable=True),
    _r("credential_request", r"\b(?:the|your) otp (?:you (?:will )?(?:receive|received|get))\b"),
    _r("credential_request", r"\b(?:verify|confirm|update|validate|re-?activate) your (?:identity|account|"
                             r"details|information|profile)\b",
       weight=0.3, detail="Asking you to 'verify your account' is how phishing pages collect logins.",
       negatable=True),
    _r("credential_request", rf"\b{_FR_CRED_VERBS}\b[^.!?\n]{{0,40}}?\b{_FR_CRED_OBJECTS}", negatable=True),
    _r("credential_request", r"\b(?:avoy|donn)\b[^.!?\n]{0,25}?\b(?:kod|otp|pin|password)\b"),
    _r("credential_request", r"\b(?:met|mete|rant|ranpli|konfirm[eé]?|verifye)\b[^.!?\n]{0,20}?\b(?:ou )?(?:detay|kod|"
                             r"informasion|nimero kart|password|pin)\b"),

    # ---- Payment redirection ---------------------------------------------
    _r("payment_redirection", r"\b(?:new|different|updated|changed|alternative|another)\s+(?:bank\s+)?"
                              r"(?:account|bank details|iban|account number)\b"),
    _r("payment_redirection", r"\b(?:to|into|on|in) this (?:bank )?account\b"),
    _r("payment_redirection", r"\b(?:our|my) (?:bank )?(?:details|account) (?:have|has) changed\b"),
    _r("payment_redirection", r"\b(?:nouveaux? (?:compte|rib|iban|coordonn[ée]es bancaires)|sur ce compte)\b"),
    _r("payment_redirection", r"\b(?:nouvo kont|lor sa kont)\b"),

    # ---- Personal impersonation ------------------------------------------
    _r("impersonation_personal", r"\bhi,? (?:mum|mom|mam|dad|mummy|daddy|ma|grandma|granny|nana|auntie|uncle)\b"),
    _r("impersonation_personal", r"\b(?:this is|it'?s) my new (?:number|phone|mobile|whatsapp)\b"),
    _r("impersonation_personal", r"\bmy new number\b|\bnew number\b", weight=0.3),
    _r("impersonation_personal", r"\b(?:lost|broke|dropped|damaged|smashed) my (?:phone|mobile)\b"),
    _r("impersonation_personal", r"\bit'?s me\b", weight=0.15),
    _r("impersonation_personal", r"\b(?:salut|coucou) (?:maman|papa|mamie|papi)\b"),
    _r("impersonation_personal", r"\b(?:c['’]est mon )?nouveau num[ée]ro\b|\bj['’]ai perdu mon t[ée]l[ée]phone\b"),
    _r("impersonation_personal", r"\b(?:mo )?nouvo nimero\b|\bmo finn perdi mo (?:portab|telefonn)\b"),
    _r("impersonation_personal", r"\bmo (?:telefonn|portab) (?:finn )?(?:tonbe|tombe|kase|perdi|gate)\b|"
                                 r"\bse mwa (?:ou )?(?:garson|tifi|zanfan|frer|ser)\b|\bmo dan (?:problem|traka)\b"),

    # ---- Unusual payment method ---------------------------------------
    _r("unusual_payment", r"\b(?:usdt|bitcoin|btc|ethereum|crypto(?:currency|currencies)?|binance|tether|"
                          r"trc-?20|erc-?20)\b"),
    _r("unusual_payment", r"\b(?:gift|itunes|google play|steam|amazon|apple|voucher) cards?\b"),
    _r("unusual_payment", r"\b(?:western union|moneygram)\b", weight=0.3),

    # ---- Channel switch ------------------------------------------------
    _r("contact_switch", r"\b(?:call|contact|whatsapp|text|message|ring)\s+(?:us|me|our agent|this number|the number|"
                         r"our hotline)\b"),
    _r("contact_switch", r"\b(?:appelez|contactez)(?:-nous| le)\b|\bsonn lor\b"),
    _r("suspicious_link", r"\bklik (?:lor|isi|la|sa)\b", weight=0.1),
    _r("suspicious_link", r"\bclick (?:here|the link|below|this link)\b", weight=0.1),
]

_NEGATION = re.compile(r"\b(?:never|do not|don'?t|not|no one will|jamais|ne pas|ne partagez)\b[^.!?\n]*$", FLAGS)

TRUST_PATTERNS = [
    (re.compile(r"\b(?:never|do not|don'?t) share (?:this|your|the)\b[^.!?\n]{0,30}(?:code|otp|pin)", FLAGS),
     "Reminds you never to share your code, as genuine bank messages do."),
    (re.compile(r"\bne (?:partagez|communiquez) jamais\b", FLAGS),
     "Reminds you never to share your code, as genuine bank messages do."),
    (re.compile(r"\bif (?:this|it) wasn'?t you\b[^.!?\n]{0,60}(?:app|card|official)", FLAGS),
     "Points you to your usual app or card rather than a link."),
]


def _is_negated(text: str, start: int) -> bool:
    window = text[max(0, start - 30):start]
    return bool(_NEGATION.search(window))


def detect(ctx: DetectionContext) -> list[Signal]:
    signals: list[Signal] = []
    for rule in RULES:
        for m in rule.pattern.finditer(ctx.text):
            if rule.negatable and _is_negated(ctx.text, m.start()):
                continue
            signals.append(Signal(
                tactic=rule.tactic,
                evidence=m.group(0),
                start=m.start(),
                end=m.end(),
                weight=rule.weight,
                detail=rule.detail,
            ))
    for pattern, note in TRUST_PATTERNS:
        if pattern.search(ctx.text) and note not in ctx.trust_notes:
            ctx.trust_notes.append(note)
    return signals


_FR_WORDS = re.compile(r"\b(?:vous|votre|vos|le|la|les|est|pour|avec|compte|aujourd['’]hui|veuillez|merci)\b", FLAGS)
_MFE_WORDS = re.compile(r"\b(?:ou|mo|finn|pou|avoy|pa|sa|enn|bonzour|nimero|kont|ki|lor|dan|kas|zot)\b", FLAGS)
_EN_WORDS = re.compile(r"\b(?:the|your|you|is|to|and|of|this|please|account|with|have|will)\b", FLAGS)


def detect_language(text: str) -> str:
    """Very small heuristic: 'en', 'fr' or 'mfe' (Kreol Morisien)."""
    scores = {
        "en": len(_EN_WORDS.findall(text)),
        "fr": len(_FR_WORDS.findall(text)),
        "mfe": len(_MFE_WORDS.findall(text)),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "en"
