"""
Diceware-Style Passphrase Generator
=====================================
Generates memorable passphrases from a curated word list using
cryptographically secure random selection (secrets module).
"""

import math
import secrets
from dataclasses import dataclass
from typing import List

# Curated EFF-inspired word list (subset — high-quality, memorable words)
WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt",
    "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
    "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce",
    "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart",
    "apple", "apology", "appear", "apply", "arena", "argue", "armor", "army",
    "arrange", "arrest", "arrive", "arrow", "artist", "artwork", "aspect", "attack",
    "attend", "attract", "auction", "audit", "august", "aunt", "author", "auto",
    "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome", "awful",
    "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance",
    "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty",
    "become", "beef", "before", "begin", "behave", "behind", "believe", "below",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blue", "blur", "blush", "board", "boat", "body", "boil",
    "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
    "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk",
    "bullet", "bundle", "bunny", "burden", "burger", "burst", "bus", "business",
    "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
    "cage", "cake", "call", "calm", "camera", "camp", "canal", "cancel",
    "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain",
    "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter",
    "charge", "charm", "chart", "chase", "cheap", "check", "cheese", "cherry",
    "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic",
    "chunk", "church", "cigar", "cinnamon", "circle", "citizen", "city", "civil",
    "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever",
    "cliff", "climb", "clinic", "clip", "clock", "close", "cloth", "cloud",
    "clown", "club", "cluster", "clutch", "coach", "coast", "coconut", "code",
    "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy",
    "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country",
    "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft",
    "crane", "crash", "crater", "crazy", "cream", "credit", "creek", "crew",
    "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
    "crucial", "cruel", "cruise", "crumble", "crush", "crystal", "cube", "culture",
    "cup", "curious", "current", "curtain", "curve", "cushion", "custom", "cycle",
    "daddy", "damage", "damp", "dance", "danger", "daring", "dash", "daughter",
    "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
    "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree",
    "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart",
    "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design",
    "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote",
    "diagram", "diamond", "diary", "diesel", "diet", "differ", "digital", "dignity",
    "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease",
    "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "dizzy",
    "doctor", "document", "dodge", "dolphin", "domain", "donate", "donkey", "donor",
    "door", "dose", "double", "dove", "dragon", "drama", "drastic", "draw",
    "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily",
    "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate",
    "effort", "eight", "either", "elbow", "elder", "electric", "elegant", "element",
    "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge",
    "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy",
    "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry",
    "envelope", "episode", "equal", "equip", "erode", "erosion", "error", "erupt",
    "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic",
    "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
    "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion",
    "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal",
    "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever",
    "fiber", "fiction", "field", "figure", "file", "film", "filter", "final",
    "find", "finger", "finish", "fire", "firm", "fiscal", "fish", "fitness",
    "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip",
    "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force",
    "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
    "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe",
    "frog", "front", "frost", "frozen", "fruit", "fuel", "fun", "funny",
    "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game",
    "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine",
    "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "glad",
    "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory",
    "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose",
    "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain",
    "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief",
    "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster",
    "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have",
    "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height",
    "hello", "helmet", "help", "hero", "hip", "hire", "history", "hobby",
    "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood",
    "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
    "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon",
    "idea", "identify", "idle", "ignore", "illegal", "illness", "image", "imitate",
    "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include",
    "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict",
    "inform", "inhale", "inherit", "initial", "inject", "inmate", "inner", "innocent",
    "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact",
    "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate",
    "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous",
    "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy",
    "judge", "juice", "jump", "jungle", "junior", "junk", "jury", "just",
    "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney",
    "kind", "kingdom", "kiss", "kitchen", "kite", "kitten", "kiwi", "knee",
    "knife", "knock", "know", "labor", "ladder", "lady", "lake", "lamp",
    "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "legend", "leisure", "lemon", "lend", "length", "lens",
    "leopard", "lesson", "letter", "level", "liberty", "library", "license", "life",
    "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
    "list", "little", "live", "lizard", "load", "loan", "lobster", "local",
    "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury",
    "lyrics", "machine", "magic", "magnet", "maid", "mail", "major", "make",
    "mammal", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble",
    "march", "margin", "marine", "market", "marriage", "mask", "mass", "master",
    "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow",
    "mean", "measure", "media", "melody", "melt", "member", "memory", "mention",
    "mentor", "mercy", "merge", "merit", "merry", "mesh", "message", "metal",
    "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
    "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor",
    "monkey", "monster", "month", "moon", "moral", "morning", "mosquito", "mother",
    "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin",
    "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual",
    "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty",
    "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither",
    "nephew", "nerve", "nest", "network", "neutral", "never", "news",
]


@dataclass
class GeneratedPassphrase:
    """A generated passphrase with metadata."""
    passphrase: str
    word_count: int
    separator: str
    entropy_bits: float
    words_used: list
    total_length: int


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True,
    add_symbol: bool = False,
) -> GeneratedPassphrase:
    """
    Generate a Diceware-style passphrase.

    Args:
        word_count: Number of words (4-8)
        separator: Word separator (space, -, ., none)
        capitalize: Randomly capitalize some words
        add_number: Insert a random digit
        add_symbol: Append a random symbol

    Returns:
        GeneratedPassphrase with the passphrase and metadata
    """
    word_count = max(3, min(8, word_count))

    # Select random words
    words = [secrets.choice(WORDLIST) for _ in range(word_count)]

    # Capitalize random words
    if capitalize:
        cap_count = max(1, word_count // 2)
        cap_indices = set()
        while len(cap_indices) < cap_count:
            cap_indices.add(secrets.randbelow(word_count))
        for idx in cap_indices:
            words[idx] = words[idx].capitalize()

    # Build passphrase
    passphrase = separator.join(words)

    # Add random digit
    if add_number:
        digit = str(secrets.randbelow(10))
        insert_pos = secrets.randbelow(len(passphrase))
        passphrase = passphrase[:insert_pos] + digit + passphrase[insert_pos:]

    # Add random symbol
    if add_symbol:
        symbols = "!@#$%&*?"
        sym = secrets.choice(symbols)
        passphrase += sym

    # Calculate entropy (based on wordlist size and word count)
    entropy_bits = round(math.log2(len(WORDLIST)) * word_count, 2)
    if add_number:
        entropy_bits += math.log2(10)
    if add_symbol:
        entropy_bits += math.log2(8)

    return GeneratedPassphrase(
        passphrase=passphrase,
        word_count=word_count,
        separator=separator,
        entropy_bits=round(entropy_bits, 2),
        words_used=words,
        total_length=len(passphrase),
    )


def generate_batch_passphrases(
    count: int = 5,
    **kwargs,
) -> List[GeneratedPassphrase]:
    """Generate multiple passphrases with the same configuration."""
    count = max(1, min(20, count))
    return [generate_passphrase(**kwargs) for _ in range(count)]
