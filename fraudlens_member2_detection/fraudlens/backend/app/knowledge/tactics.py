"""Catalogue of scam manipulation tactics.

Every warning sign the engine produces is tagged with one of these tactics.
The same catalogue drives the colours in the app, the score weights and the
micro-lessons in the Learn tab, so adding a tactic here is the only place you
need to touch to introduce a new one.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tactic:
    id: str
    label: str
    short: str            # 1-3 word chip label
    description: str      # why it matters, shown under the warning sign
    weight: float         # base risk weight, 0..1
    color: str            # hex colour used for highlights in the app
    icon: str             # Material icon name (used by the mobile app)
    lesson: str           # 30-second micro-lesson
    safe_action: str      # what to do instead
    examples: list[str] = field(default_factory=list)


TACTICS: dict[str, Tactic] = {
    t.id: t
    for t in [
        Tactic(
            id="urgency",
            label="Pressure to act fast",
            short="Urgency",
            description="Scammers rush you so you don't stop to think or check with someone.",
            weight=0.25,
            color="#F59E0B",
            icon="TIMER",
            lesson="Real banks and companies give you time. A deadline like 'within 2 hours' or "
                   "'today only' is designed to stop you from thinking clearly.",
            safe_action="Slow down. No genuine payment is so urgent that you can't take 10 minutes to verify it.",
            examples=["within 2 hours", "act now", "today only", "vit vit"],
        ),
        Tactic(
            id="authority",
            label="Claims to be an official organisation",
            short="Authority",
            description="The message uses the name of a bank, post office or government body to earn your trust.",
            weight=0.20,
            color="#6366F1",
            icon="ACCOUNT_BALANCE",
            lesson="Anyone can type 'MCB' or 'Mauritius Post' into a message. A familiar name is not proof "
                   "of who sent it.",
            safe_action="Contact the organisation yourself using the number on your card or its official website.",
            examples=["Dear customer", "Security Department", "Bank of Mauritius"],
        ),
        Tactic(
            id="threat",
            label="Threats or fear",
            short="Threat",
            description="Warnings about blocked accounts, fines or police are used to frighten you into acting.",
            weight=0.30,
            color="#EF4444",
            icon="WARNING_AMBER",
            lesson="Fear switches off careful thinking. Banks do not close accounts or send police by SMS.",
            safe_action="Ignore the threat and check your account through your usual banking app.",
            examples=["account will be suspended", "legal action", "compte bloqué"],
        ),
        Tactic(
            id="secrecy",
            label="Asks you to keep it secret",
            short="Secrecy",
            description="Scammers isolate you from people who could spot the scam.",
            weight=0.35,
            color="#A855F7",
            icon="VISIBILITY_OFF",
            lesson="If someone asks you not to tell your family or your bank, that is exactly who you should tell.",
            safe_action="Talk to someone you trust before doing anything.",
            examples=["don't tell anyone", "keep this confidential", "pa dir personn"],
        ),
        Tactic(
            id="reward",
            label="Too good to be true",
            short="Too good",
            description="Prizes, guaranteed profits or 'risk-free' returns are classic bait.",
            weight=0.35,
            color="#10B981",
            icon="CARD_GIFTCARD",
            lesson="Nobody guarantees high returns with no risk, and you can't win a lottery you never entered.",
            safe_action="Check whether the company is licensed by the Financial Services Commission (FSC).",
            examples=["guaranteed returns", "you have won", "double your money"],
        ),
        Tactic(
            id="payment_request",
            label="Asks you to send money",
            short="Payment",
            description="The message asks for a payment, fee or transfer.",
            weight=0.25,
            color="#F97316",
            icon="PAYMENTS",
            lesson="Small 'release fees' or 'processing fees' are a common hook. Once you pay one, more follow.",
            safe_action="Never pay because a message told you to. Verify the request through a channel you already trust.",
            examples=["pay a fee", "transfer Rs", "release fee"],
        ),
        Tactic(
            id="credential_request",
            label="Asks for codes or passwords",
            short="OTP / PIN",
            description="Requests for your OTP, PIN, password or card details are the strongest scam signal.",
            weight=0.55,
            color="#DC2626",
            icon="PASSWORD",
            lesson="Your OTP is the key to your account. Your bank will never ask for it, by SMS, phone or WhatsApp.",
            safe_action="Never share an OTP, PIN, CVV or password with anyone.",
            examples=["reply with the OTP", "confirm your PIN", "code de vérification"],
        ),
        Tactic(
            id="suspicious_link",
            label="Suspicious link",
            short="Link",
            description="The link hides its real destination or imitates an official website.",
            weight=0.30,
            color="#0EA5E9",
            icon="LINK_OFF",
            lesson="Scam links often look almost right: 'mcb-secure-verify.com' is not 'mcb.mu'. Short links hide where they go.",
            safe_action="Don't tap the link. Open your bank's app or type the official address yourself.",
            examples=["bit.ly/...", "mcb-secure-verify.com"],
        ),
        Tactic(
            id="payment_redirection",
            label="New or changed bank details",
            short="New account",
            description="Being told to pay a new or different account is how invoice and family scams steal money.",
            weight=0.45,
            color="#E11D48",
            icon="SWAP_HORIZ",
            lesson="If bank details change by message, confirm by calling the person on a number you already had.",
            safe_action="Confirm new bank details by phone using a number you already know.",
            examples=["our new account", "updated bank details", "this account"],
        ),
        Tactic(
            id="impersonation_personal",
            label="Pretends to be someone you know",
            short="Impersonation",
            description="'Hi Mum, this is my new number' is a common way to borrow the trust of a loved one.",
            weight=0.40,
            color="#DB2777",
            icon="PERSON_SEARCH",
            lesson="A new number plus a money request is a red flag even if the tone sounds exactly like your child.",
            safe_action="Call the person on their old number or ask a question only they could answer.",
            examples=["Hi Mum", "this is my new number", "mo nouvo nimero"],
        ),
        Tactic(
            id="unusual_payment",
            label="Unusual payment method",
            short="Crypto / gift card",
            description="Crypto, gift cards and wire services are hard to trace and nearly impossible to reverse.",
            weight=0.45,
            color="#84CC16",
            icon="CURRENCY_BITCOIN",
            lesson="Legitimate businesses don't ask for payment in gift cards or crypto to a private wallet.",
            safe_action="Refuse any request to pay with crypto or gift cards.",
            examples=["send USDT", "Google Play card", "bitcoin wallet"],
        ),
        Tactic(
            id="threat_intel",
            label="Flagged by security databases",
            short="Blocklisted",
            description="Independent security services report this link or number as dangerous or brand-new.",
            weight=0.6,
            color="#7F1D1D",
            icon="GPP_BAD",
            lesson="Google Safe Browsing and malware databases track millions of dangerous sites. Scam websites "
                   "are also usually registered just days before the SMS campaign starts.",
            safe_action="Never open a link that security services have flagged, even if the message looks real.",
            examples=["Flagged by Google Safe Browsing", "website registered 2 days ago"],
        ),
        Tactic(
            id="sender_mismatch",
            label="Sender doesn't match who it claims to be",
            short="Wrong sender",
            description="The message claims to come from an organisation but was sent from a personal phone number.",
            weight=0.45,
            color="#9333EA",
            icon="PHONELINK_ERASE",
            lesson="Banks and couriers send SMS from their registered name (like 'MCB'), not from a random "
                   "mobile number. A 'bank' texting from +230 5xxx xxxx is a strong red flag.",
            safe_action="Ignore messages from personal numbers that claim to be an organisation.",
            examples=["'MCB ALERT' sent from +230 5821 4470"],
        ),
        Tactic(
            id="contact_switch",
            label="Pushes you to another channel",
            short="Call / chat",
            description="Asking you to call a number or move to WhatsApp takes you away from official channels.",
            weight=0.15,
            color="#64748B",
            icon="PHONE_FORWARDED",
            lesson="Scammers give you their own 'hotline'. Use the number printed on your card instead.",
            safe_action="Only call numbers you have looked up yourself.",
            examples=["call this number", "WhatsApp us on"],
        ),
    ]
}

COMBO_LABEL = "Dangerous combination"
