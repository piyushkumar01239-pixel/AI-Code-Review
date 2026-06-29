import re
import os
from groq import Groq

PATTERNS = [
    {
        'severity': 'critical',
        'title': 'Hardcoded password or secret',
        'regex': r'(?i)(password|passwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']',
        'description': 'A secret value is hardcoded in the source code. Anyone with access to the code can read it.',
        'fix': 'Use environment variables instead: os.environ.get("PASSWORD")',
    },
    {
        'severity': 'critical',
        'title': 'Potential SQL Injection',
        'regex': r'(?i)(execute|cursor\.execute)\s*\(\s*[f"\'].*(\+|{|})',
        'description': 'SQL queries built with string formatting allow attackers to inject arbitrary SQL.',
        'fix': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    },
    {
        'severity': 'high',
        'title': 'Dangerous use of eval()',
        'regex': r'\beval\s*\(',
        'description': 'eval() executes arbitrary code. If user input reaches eval(), attackers can run any code.',
        'fix': 'Replace eval() with safer alternatives like ast.literal_eval() for parsing data.',
    },
    {
        'severity': 'high',
        'title': 'Dangerous use of exec()',
        'regex': r'\bexec\s*\(',
        'description': 'exec() runs arbitrary code strings. It is a critical attack vector if input comes from a user.',
        'fix': 'Refactor your code to remove exec() entirely.',
    },
    {
        'severity': 'critical',
        'title': 'Unsafe deserialization with pickle',
        'regex': r'pickle\.(load|loads)\s*\(',
        'description': 'Deserializing untrusted data with pickle can execute arbitrary code.',
        'fix': 'Use JSON instead of pickle for data exchange with untrusted sources.',
    },
    {
        'severity': 'high',
        'title': 'Weak cryptographic hash (MD5/SHA1)',
        'regex': r'(?i)(md5|sha1)\s*\(',
        'description': 'MD5 and SHA-1 are cryptographically broken and should not be used for security.',
        'fix': 'Use SHA-256 or bcrypt instead.',
    },
    {
        'severity': 'medium',
        'title': 'Flask debug mode enabled',
        'regex': r'app\.run\s*\(.*debug\s*=\s*True',
        'description': 'Running Flask with debug=True in production exposes an interactive debugger to attackers.',
        'fix': 'Set debug=False in production or use environment variables to control it.',
    },
    {
        'severity': 'critical',
        'title': 'Potential Command Injection',
        'regex': r'(os\.system|subprocess\.call|subprocess\.run|popen)\s*\(.*(\+|f["\'])',
        'description': 'Building shell commands with user input allows attackers to inject OS commands.',
        'fix': 'Pass commands as a list: subprocess.run(["ls", user_dir], shell=False)',
    },
]


def scan_code(code):
    findings = []
    for pattern in PATTERNS:
        regex = re.compile(pattern['regex'], re.MULTILINE)
        for match in regex.finditer(code):
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'severity': pattern['severity'],
                'title': pattern['title'],
                'description': pattern['description'],
                'line_number': line_num,
                'fix': pattern['fix'],
            })
    return findings


def calculate_score(findings):
    deductions = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
    score = 100
    for f in findings:
        score -= deductions.get(f['severity'], 0)
    return max(0, score)


def get_ai_summary(code, findings, language):
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        return None
    try:
        client = Groq(api_key=api_key)
        findings_text = '\n'.join(
            f"- [{f['severity'].upper()}] {f['title']} on line {f['line_number']}"
            for f in findings
        ) if findings else '- No issues detected'

        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            max_tokens=300,
            messages=[{
                'role': 'user',
                'content': (
                    f"You are a security code reviewer. Briefly summarize these findings "
                    f"for a developer scanning {language} code. Be friendly and concise (3-4 sentences max).\n\n"
                    f"Findings:\n{findings_text}"
                )
            }]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"AI summary failed: {e}")
        return None