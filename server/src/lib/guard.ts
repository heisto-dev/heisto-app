/** Prompt-injection risk scoring for the Guard API (heuristic layer). */
const RULES: [RegExp, number, string][] = [
  [/(ignore|disregard|override) (?:(?:your|all|any|the) )?(?:(?:previous|prior|above) )?(instructions?|rules?|prompts?|directives?|constraints?|safeguards?|polic(?:y|ies)|context)\b|ignore (?:all |any )?(previous|prior|above)\b|forget (everything above|all previous|previous instructions)/i, 0.65, 'instruction_override'],
  [/system (prompt|instructions)|instructions above|reveal (your|the) (prompt|instructions|rules)|repeat (everything|the text) above/i, 0.3, 'prompt_leakage'],
  [/you are now|pretend (to be|you are)|role.?play|act as (a|an|my)|from now on you/i, 0.22, 'role_hijack'],
  [/[A-Za-z0-9+/]{32,}={0,2}/, 0.2, 'encoded_payload'],
  [/\bdan\b|jailbreak|no restrictions|developer mode|unfiltered/i, 0.4, 'known_jailbreak'],
  [/transfer (all|the)?\s*(funds|tokens|sol|usdc)|send (all|the) (funds|tokens)|withdraw (all|everything)|private key|seed phrase|mnemonic/i, 0.35, 'financial_action'],
  [/password|secret (word|key|code)|api[ _-]?key/i, 0.15, 'secret_request'],
  [/<\/?(system|assistant|instructions?)>|\[\/?INST\]|###\s*(system|instruction)/i, 0.3, 'delimiter_injection'],
];

// Match separated/obfuscated keywords only in a suspicious phrase, not every
// occurrence of "ignore" or "system". This is still a heuristic, not a proof.
const COMPACT_RULES: Record<string, RegExp> = {
  instruction_override: /(ignore|disregard|override)(your|all|any|the)?(previous|prior|above)?(instructions?|rules?|prompts?|directives?|constraints?|safeguards?|polic(y|ies)|context)|ignore(all|any)?(previous|prior|above)|forget(everythingabove|allprevious|previousinstructions)/,
  prompt_leakage: /system(prompt|instructions)|instructionsabove|reveal(your|the)(prompt|instructions|rules)|repeat(everything|thetext)above/,
  role_hijack: /youarenow|pretend(tobe|youare)|roleplay|actas(a|an|my)|fromnowonyou/,
  known_jailbreak: /jailbreak|norestrictions|developermode|unfiltered/,
  financial_action: /transfer(all|the)?(funds|tokens|sol|usdc)|send(all|the)(funds|tokens)|withdraw(all|everything)|privatekey|seedphrase|mnemonic/,
  secret_request: /password|secret(word|key|code)|apikey/,
};

function normalize(input: string) {
  // NFKC handles fullwidth/compatibility characters. Remove format controls,
  // zero-width characters and combining marks before whitespace normalization.
  const plain = input.normalize('NFKC').normalize('NFD')
    .replace(/[\p{Cf}\p{Mn}]/gu, '').toLowerCase().replace(/\s+/gu, ' ').trim();
  const substitutions: Record<string, string> = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i',
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  };
  const folded = plain.replace(/[013457@$!аеіорсху]/gu, c => substitutions[c]);
  return { plain, compact: folded.replace(/[^a-z0-9]/g, '') };
}

export interface GuardResult {
  score: number; action: 'allow' | 'flag' | 'block'; categories: string[]; owasp: 'LLM01';
  method: 'heuristic-rules-v2';
  warning: string;
}

export function guardScore(input: string): GuardResult {
  const { plain, compact } = normalize(input);
  let score = 0.03;
  const categories: string[] = [];
  for (const [re, w, name] of RULES) {
    if (re.test(input) || re.test(plain) || COMPACT_RULES[name]?.test(compact)) {
      score += w; categories.push(name);
    }
  }
  score = Math.min(0.99, Math.round(score * 100) / 100);
  return {
    score, action: score >= 0.6 ? 'block' : score >= 0.3 ? 'flag' : 'allow', categories, owasp: 'LLM01',
    method: 'heuristic-rules-v2',
    warning: 'A heuristic risk score, not a probability or a guarantee of safety. Use independent authorization and data-access controls.',
  };
}

/** Objectives that would turn the arena into a harmful-content generator are refused at deploy. */
const FORBIDDEN_OBJECTIVES = /\b(bomb|explosive|nerve agent|bioweapon|pathogen|anthrax|ricin|sarin|weapon(s)? of mass|meth(amphetamine)?|fentanyl synthesis|malware|ransomware|keylogger|exploit code|credit card numbers|csam|child sexual|sexual content involving minors|self[- ]harm instructions|suicide method)\b/i;
export function objectiveAllowed(...texts: string[]) {
  return !texts.some(t => FORBIDDEN_OBJECTIVES.test(t));
}
