package blackmarker.rules;

import blackmarker.model.MaskingRule;
import blackmarker.model.RuleCategory;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory providing 60+ built-in masking rules covering PII, auth tokens,
 * infrastructure details, crypto keys, and session data.
 */
public final class DefaultRules {

    private DefaultRules() {}

    public static List<MaskingRule> createAll() {
        List<MaskingRule> rules = new ArrayList<>();
        rules.addAll(createPiiRules());
        rules.addAll(createAuthRules());
        rules.addAll(createInfrastructureRules());
        rules.addAll(createCryptoRules());
        rules.addAll(createSessionRules());
        return rules;
    }

    // =====================================================================
    // PII / Personal Data
    // =====================================================================
    public static List<MaskingRule> createPiiRules() {
        List<MaskingRule> rules = new ArrayList<>();

        rules.add(new MaskingRule(
            "Email Address",
            "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
            RuleCategory.PII,
            "Matches standard email addresses"
        ));

        rules.add(new MaskingRule(
            "Phone (International)",
            "(?:\\+?\\d{1,3}[\\-\\s.]?)?\\(?\\d{2,4}\\)?[\\-\\s.]?\\d{3,4}[\\-\\s.]?\\d{3,4}",
            RuleCategory.PII,
            "International phone number formats"
        ));

        rules.add(new MaskingRule(
            "SSN (US)",
            "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            RuleCategory.PII,
            "US Social Security Numbers"
        ));

        rules.add(new MaskingRule(
            "Credit Card (Generic)",
            "\\b(?:\\d{4}[\\-\\s]?){3}\\d{4}\\b",
            RuleCategory.PII,
            "16-digit card numbers with optional separators"
        ));

        rules.add(new MaskingRule(
            "Credit Card (Amex)",
            "\\b3[47]\\d{2}[\\-\\s]?\\d{6}[\\-\\s]?\\d{5}\\b",
            RuleCategory.PII,
            "American Express card numbers"
        ));

        rules.add(new MaskingRule(
            "IBAN",
            "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}\\b",
            RuleCategory.PII,
            "International Bank Account Numbers"
        ));

        rules.add(new MaskingRule(
            "IPv4 Address",
            "(?<!/)\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
            RuleCategory.PII,
            "IPv4 addresses (skips version strings like Chrome/x.x.x.x)"
        ));

        rules.add(new MaskingRule(
            "IPv6 Address",
            "\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b",
            RuleCategory.PII,
            "Full IPv6 addresses"
        ));

        rules.add(new MaskingRule(
            "IPv6 Address (Compressed)",
            "\\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\\b",
            RuleCategory.PII,
            "Compressed IPv6 addresses with ::"
        ));

        rules.add(new MaskingRule(
            "MAC Address",
            "\\b(?:[0-9a-fA-F]{2}[:\\-]){5}[0-9a-fA-F]{2}\\b",
            RuleCategory.PII,
            "Network MAC addresses"
        ));

        rules.add(new MaskingRule(
            "Date of Birth (JSON/Form)",
            "(?:dob|date_of_birth|birthdate|birthday)[\"'\\s:=]+[\"']?(\\d{4}[\\-/]\\d{2}[\\-/]\\d{2})[\"']?",
            RuleCategory.PII, '\u2588', true, true,
            "Date of birth — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Passport Number",
            "(?:passport[_\\-\\s]?(?:no|number|num|id))[\"'\\s:=]+[\"']?([A-Z0-9]{6,12})[\"']?",
            RuleCategory.PII, '\u2588', true, true,
            "Passport number — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Driver License",
            "(?:driver[_\\-\\s]?(?:license|licence|lic)[_\\-\\s]?(?:no|number|num|id)?)[\"'\\s:=]+[\"']?([A-Z0-9]{5,15})[\"']?",
            RuleCategory.PII, '\u2588', true, true,
            "Driver license — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Full Name (JSON key)",
            "(?:full[_\\-]?name|first[_\\-]?name|last[_\\-]?name|surname|given[_\\-]?name|family[_\\-]?name)[\"'\\s:=]+[\"']([^\"']+)[\"']",
            RuleCategory.PII, '\u2588', true, true,
            "Names — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Address (JSON key)",
            "(?:street|address|addr|city|zip[_\\-]?code|postal[_\\-]?code|state|province|country)[\"'\\s:=]+[\"']([^\"']+)[\"']",
            RuleCategory.PII, '\u2588', true, true,
            "Address — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Tax ID / TIN",
            "(?:tax[_\\-\\s]?id|tin|tax[_\\-\\s]?number|ssn|ein)[\"'\\s:=]+[\"']?([A-Z0-9\\-]{5,15})[\"']?",
            RuleCategory.PII, '\u2588', true, true,
            "Tax ID / SSN / EIN — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "National ID",
            "(?:national[_\\-\\s]?id|id[_\\-\\s]?number|citizen[_\\-\\s]?id|personal[_\\-\\s]?id)[\"'\\s:=]+[\"']?([A-Z0-9\\-]{5,20})[\"']?",
            RuleCategory.PII, '\u2588', true, true,
            "National ID — masks value, preserves key name",
            1, false
        ));

        return rules;
    }

    // =====================================================================
    // Authentication & Secrets
    // =====================================================================
    public static List<MaskingRule> createAuthRules() {
        List<MaskingRule> rules = new ArrayList<>();

        rules.add(new MaskingRule(
            "Bearer Token",
            "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*",
            RuleCategory.AUTH,
            "OAuth Bearer tokens in Authorization header"
        ));

        rules.add(new MaskingRule(
            "JWT Token",
            "eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_.+/=]*",
            RuleCategory.AUTH,
            "JSON Web Tokens (header.payload.signature)"
        ));

        rules.add(new MaskingRule(
            "Basic Auth",
            "Basic\\s+[A-Za-z0-9+/]+=*",
            RuleCategory.AUTH,
            "HTTP Basic Authentication credentials"
        ));

        rules.add(new MaskingRule(
            "API Key (Generic)",
            "(?:api[_\\-]?key|apikey|api[_\\-]?token|access[_\\-]?key)[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{16,})[\"']?",
            RuleCategory.AUTH, '\u2588', true, true,
            "Generic API key — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Password (Form/JSON)",
            "(?:password|passwd|pwd|pass|secret|credential)[\"'\\s:=]+[\"']?([^\\s\"'&]{1,})[\"']?",
            RuleCategory.AUTH, '\u2588', true, true,
            "Password fields — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Authorization Header",
            "Authorization:\\s*(?:\\S+\\s+)?(.+)",
            RuleCategory.AUTH, '\u2588', true, true,
            "Authorization header — masks credential, preserves scheme (Bearer/Basic/etc)",
            1, true
        ));

        rules.add(new MaskingRule(
            "X-API-Key Header",
            "X-API-Key:\\s*(.+)",
            RuleCategory.AUTH, '\u2588', true, true,
            "X-API-Key header — masks value, preserves header name",
            1, true
        ));

        rules.add(new MaskingRule(
            "AWS Access Key ID",
            "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            RuleCategory.AUTH,
            "Amazon Web Services Access Key IDs"
        ));

        rules.add(new MaskingRule(
            "AWS Secret Access Key",
            "(?:aws[_\\-]?secret[_\\-]?(?:access[_\\-]?)?key)[\"'\\s:=]+[\"']?([A-Za-z0-9/+=]{40})[\"']?",
            RuleCategory.AUTH, '\u2588', true, true,
            "AWS Secret Access Key — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Google API Key",
            "AIza[0-9A-Za-z\\-_]{35}",
            RuleCategory.AUTH,
            "Google Cloud API keys"
        ));

        rules.add(new MaskingRule(
            "Google OAuth Token",
            "ya29\\.[0-9A-Za-z\\-_]+",
            RuleCategory.AUTH,
            "Google OAuth 2.0 access tokens"
        ));

        rules.add(new MaskingRule(
            "GitHub Token (Fine-grained)",
            "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
            RuleCategory.AUTH,
            "GitHub personal access tokens"
        ));

        rules.add(new MaskingRule(
            "GitHub PAT (Classic)",
            "github_pat_[A-Za-z0-9_]{22,}",
            RuleCategory.AUTH,
            "GitHub classic personal access tokens"
        ));

        rules.add(new MaskingRule(
            "GitLab Token",
            "glpat-[A-Za-z0-9\\-]{20,}",
            RuleCategory.AUTH,
            "GitLab personal access tokens"
        ));

        rules.add(new MaskingRule(
            "Slack Token",
            "xox[bpors]-[A-Za-z0-9\\-]{10,}",
            RuleCategory.AUTH,
            "Slack API tokens (bot, user, etc.)"
        ));

        rules.add(new MaskingRule(
            "Slack Webhook URL",
            "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            RuleCategory.AUTH,
            "Slack incoming webhook URLs"
        ));

        rules.add(new MaskingRule(
            "Discord Token",
            "[MN][A-Za-z0-9]{23,}\\.[\\w\\-]{6}\\.[\\w\\-]{27,}",
            RuleCategory.AUTH,
            "Discord bot/user tokens"
        ));

        rules.add(new MaskingRule(
            "Discord Webhook URL",
            "https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[\\w\\-]+",
            RuleCategory.AUTH,
            "Discord webhook URLs"
        ));

        rules.add(new MaskingRule(
            "Stripe API Key",
            "(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}",
            RuleCategory.AUTH,
            "Stripe secret/publishable/restricted keys"
        ));

        rules.add(new MaskingRule(
            "Twilio API Key",
            "SK[0-9a-fA-F]{32}",
            RuleCategory.AUTH,
            "Twilio API keys"
        ));

        rules.add(new MaskingRule(
            "SendGrid API Key",
            "SG\\.[A-Za-z0-9\\-_]{22}\\.[A-Za-z0-9\\-_]{43}",
            RuleCategory.AUTH,
            "SendGrid API keys"
        ));

        rules.add(new MaskingRule(
            "Mailgun API Key",
            "key-[0-9a-zA-Z]{32}",
            RuleCategory.AUTH,
            "Mailgun API keys"
        ));

        rules.add(new MaskingRule(
            "npm Token",
            "npm_[A-Za-z0-9]{36}",
            RuleCategory.AUTH,
            "npm access tokens"
        ));

        rules.add(new MaskingRule(
            "PyPI Token",
            "pypi-[A-Za-z0-9\\-_]{50,}",
            RuleCategory.AUTH,
            "PyPI API tokens"
        ));

        rules.add(new MaskingRule(
            "Heroku API Key",
            "(?:heroku[_\\-]?(?:api[_\\-]?)?key)[\"'\\s:=]+[\"']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\"']?",
            RuleCategory.AUTH, '\u2588', true, true,
            "Heroku API Key — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Azure Storage Key",
            "DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};",
            RuleCategory.AUTH,
            "Azure Storage connection strings"
        ));

        rules.add(new MaskingRule(
            "Telegram Bot Token",
            "\\d{8,10}:[A-Za-z0-9_\\-]{35}",
            RuleCategory.AUTH,
            "Telegram Bot API tokens"
        ));

        rules.add(new MaskingRule(
            "Facebook Access Token",
            "EAACEdEose0cBA[A-Za-z0-9]+",
            RuleCategory.AUTH,
            "Facebook/Meta Graph API access tokens"
        ));

        rules.add(new MaskingRule(
            "Twitter Bearer Token",
            "AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+",
            RuleCategory.AUTH,
            "Twitter/X API Bearer tokens"
        ));

        rules.add(new MaskingRule(
            "Shopify Access Token",
            "shpat_[a-fA-F0-9]{32}",
            RuleCategory.AUTH,
            "Shopify Admin API access tokens"
        ));

        rules.add(new MaskingRule(
            "Dropbox Access Token",
            "sl\\.[A-Za-z0-9\\-_]{100,}",
            RuleCategory.AUTH,
            "Dropbox short-lived access tokens"
        ));

        rules.add(new MaskingRule(
            "Vault Token",
            "(?:hvs|hvb|hvr)\\.[A-Za-z0-9]{24,}",
            RuleCategory.AUTH,
            "HashiCorp Vault tokens"
        ));

        rules.add(new MaskingRule(
            "Generic Secret in JSON",
            "\"[^\"]*(?:secret|token|key|password|credential|auth|private)[^\"]*\"\\s*:\\s*\"([^\"]+)\"",
            RuleCategory.AUTH, '\u2588', true, true,
            "JSON keys containing secret/token/key/password — masks value only",
            1, true
        ));

        return rules;
    }

    // =====================================================================
    // Infrastructure
    // =====================================================================
    public static List<MaskingRule> createInfrastructureRules() {
        List<MaskingRule> rules = new ArrayList<>();

        rules.add(new MaskingRule(
            "Private IPv4 (10.x.x.x)",
            "\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
            RuleCategory.INFRASTRUCTURE,
            "Private RFC1918 10.0.0.0/8 addresses"
        ));

        rules.add(new MaskingRule(
            "Private IPv4 (172.16-31.x.x)",
            "\\b172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}\\b",
            RuleCategory.INFRASTRUCTURE,
            "Private RFC1918 172.16.0.0/12 addresses"
        ));

        rules.add(new MaskingRule(
            "Private IPv4 (192.168.x.x)",
            "\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b",
            RuleCategory.INFRASTRUCTURE,
            "Private RFC1918 192.168.0.0/16 addresses"
        ));

        rules.add(new MaskingRule(
            "URL with Credentials",
            "https?://[^:]+:[^@]+@[^\\s\"']+",
            RuleCategory.INFRASTRUCTURE,
            "URLs containing embedded username:password"
        ));

        rules.add(new MaskingRule(
            "AWS S3 Bucket",
            "(?:s3://|s3\\.amazonaws\\.com/|s3-[a-z0-9\\-]+\\.amazonaws\\.com/)[a-z0-9][\\w.\\-]{1,61}[a-z0-9]",
            RuleCategory.INFRASTRUCTURE,
            "Amazon S3 bucket references"
        ));

        rules.add(new MaskingRule(
            "Database Connection String",
            "(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis|mssql|jdbc:[a-z]+)://[^\\s\"']+",
            RuleCategory.INFRASTRUCTURE,
            "Database connection URIs with potential credentials"
        ));

        rules.add(new MaskingRule(
            "Docker Registry",
            "(?:docker\\.io|gcr\\.io|ghcr\\.io|[a-z0-9]+\\.azurecr\\.io|[a-z0-9]+\\.dkr\\.ecr\\.[a-z0-9\\-]+\\.amazonaws\\.com)/[\\w./\\-]+",
            RuleCategory.INFRASTRUCTURE,
            "Docker container registry references"
        ));

        rules.add(new MaskingRule(
            "Internal Hostname",
            "\\b(?:[a-z0-9\\-]+\\.(?:internal|local|corp|intranet|private|lan|home|localdomain))\\b",
            RuleCategory.INFRASTRUCTURE,
            "Internal/corporate hostnames"
        ));

        rules.add(new MaskingRule(
            "Kubernetes Service",
            "\\b[a-z0-9\\-]+\\.[a-z0-9\\-]+\\.svc\\.cluster\\.local\\b",
            RuleCategory.INFRASTRUCTURE,
            "Kubernetes internal service DNS names"
        ));

        rules.add(new MaskingRule(
            "AWS ARN",
            "arn:aws[a-zA-Z\\-]*:[a-zA-Z0-9\\-]+:[a-z0-9\\-]*:\\d{12}:[\\w+\\-/:]+",
            RuleCategory.INFRASTRUCTURE,
            "Amazon Web Services Resource Names"
        ));

        rules.add(new MaskingRule(
            "AWS Account ID",
            "\\b\\d{12}\\b",
            RuleCategory.INFRASTRUCTURE,
            "12-digit AWS account IDs (disabled by default - too generic)"
        ));
        // Disable this by default as it's too generic
        rules.get(rules.size() - 1).setEnabled(false);

        rules.add(new MaskingRule(
            "GCP Project ID",
            "(?:project[_\\-]?id|projectId)[\"'\\s:=]+[\"']?([a-z][a-z0-9\\-]{4,28}[a-z0-9])[\"']?",
            RuleCategory.INFRASTRUCTURE, '\u2588', true, true,
            "GCP Project ID — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Azure Subscription ID",
            "(?:subscription[_\\-]?id|subscriptionId)[\"'\\s:=]+[\"']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\"']?",
            RuleCategory.INFRASTRUCTURE, '\u2588', true, true,
            "Azure Subscription ID — masks value, preserves key name",
            1, false
        ));

        rules.add(new MaskingRule(
            "Server Header",
            "Server:\\s*(.+)",
            RuleCategory.INFRASTRUCTURE, '\u2588', true, true,
            "Server header — masks value, preserves header name",
            1, false
        ));

        rules.add(new MaskingRule(
            "X-Powered-By Header",
            "X-Powered-By:\\s*(.+)",
            RuleCategory.INFRASTRUCTURE, '\u2588', true, true,
            "X-Powered-By header — masks value, preserves header name",
            1, false
        ));

        return rules;
    }

    // =====================================================================
    // Crypto & Keys
    // =====================================================================
    public static List<MaskingRule> createCryptoRules() {
        List<MaskingRule> rules = new ArrayList<>();

        rules.add(new MaskingRule(
            "PEM Private Key Header",
            "-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            RuleCategory.CRYPTO,
            "PEM-encoded private key begin marker"
        ));

        rules.add(new MaskingRule(
            "PEM Key Content",
            "-----BEGIN [A-Z\\s]+-----[\\s\\S]*?-----END [A-Z\\s]+-----",
            RuleCategory.CRYPTO,
            "Full PEM-encoded key/certificate blocks"
        ));

        rules.add(new MaskingRule(
            "Bitcoin Address",
            "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b",
            RuleCategory.CRYPTO,
            "Bitcoin legacy addresses (P2PKH/P2SH)"
        ));

        rules.add(new MaskingRule(
            "Bitcoin Bech32 Address",
            "\\bbc1[ac-hj-np-z02-9]{25,87}\\b",
            RuleCategory.CRYPTO,
            "Bitcoin Bech32/SegWit addresses"
        ));

        rules.add(new MaskingRule(
            "Ethereum Address",
            "\\b0x[0-9a-fA-F]{40}\\b",
            RuleCategory.CRYPTO,
            "Ethereum addresses (40 hex chars)"
        ));

        rules.add(new MaskingRule(
            "Long Hex String",
            "\\b[0-9a-fA-F]{40,}\\b",
            RuleCategory.CRYPTO,
            "Long hex strings (potential hashes, keys)"
        ));

        rules.add(new MaskingRule(
            "SHA256 Hash (labeled)",
            "(?:sha256|sha\\-256|hash)[\"'\\s:=]+[\"']?[0-9a-fA-F]{64}[\"']?",
            RuleCategory.CRYPTO,
            "SHA-256 hashes in key-value context"
        ));

        rules.add(new MaskingRule(
            "MD5 Hash (labeled)",
            "(?:md5|hash)[\"'\\s:=]+[\"']?[0-9a-fA-F]{32}[\"']?",
            RuleCategory.CRYPTO,
            "MD5 hashes in key-value context"
        ));

        return rules;
    }

    // =====================================================================
    // Session Data
    // =====================================================================
    public static List<MaskingRule> createSessionRules() {
        List<MaskingRule> rules = new ArrayList<>();

        // Cookie masking is handled programmatically in MaskingEngine.processCookieHeaders()
        // to avoid false positives on other headers containing ;name=value patterns

        rules.add(new MaskingRule(
            "JSESSIONID",
            "JSESSIONID[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "Java session identifiers — preserves cookie name",
            1, true
        ));

        rules.add(new MaskingRule(
            "PHPSESSID",
            "PHPSESSID[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "PHP session identifiers — preserves cookie name",
            1, true
        ));

        rules.add(new MaskingRule(
            "ASP.NET Session ID",
            "ASP\\.NET_SessionId[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "ASP.NET session identifiers — preserves cookie name",
            1, true
        ));

        rules.add(new MaskingRule(
            "CSRF Token",
            "(?:csrf[_\\-]?token|_csrf|__RequestVerificationToken|authenticity_token|csrfmiddlewaretoken|_token)[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "CSRF tokens — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Session ID (Generic)",
            "(?:session[_\\-]?id|sid|sess|session_token)[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "Generic session identifiers — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "OAuth State Parameter",
            "(?:state|nonce|code_verifier|code_challenge)[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "OAuth 2.0 state/nonce — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Refresh Token",
            "(?:refresh[_\\-]?token)[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "OAuth refresh tokens — masks value, preserves key name",
            1, true
        ));

        rules.add(new MaskingRule(
            "Access Token (Generic)",
            "(?:access[_\\-]?token)[\"'\\s:=]+[\"']?([A-Za-z0-9\\-._~+/]{8,})[\"']?",
            RuleCategory.SESSION, '\u2588', true, true,
            "Generic access tokens — masks value, preserves key name",
            1, true
        ));

        return rules;
    }
}
