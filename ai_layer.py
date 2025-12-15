import json
import re
import requests
from typing import Dict, List, Any
from config import Config

class AIAnalyzer:
    """LLM-powered analysis layer for security findings."""
    
    def __init__(self):
        self.api_key = Config.OPENAI_API_KEY
        self.base_url = Config.OPENAI_BASE_URL
        self.model = Config.LLM_MODEL
    
    def analyze_findings(self, findings: List[Dict], original_config: str, 
                        file_type: str) -> Dict[str, Any]:
        """
        Send findings to LLM for interpretation and remediation.
        
        Returns:
            {
                'diagnosis': str,
                'severity_justification': str,
                'remediation_steps': List[str],
                'improved_config': str,
                'overall_risk_score': int (0-100)
            }
        """
        
        if not findings:
            return {
                'diagnosis': 'No security issues detected.',
                'severity_justification': 'The configuration passed all static analysis checks.',
                'remediation_steps': [],
                'improved_config': original_config,
                'overall_risk_score': 0
            }
        
        # Build structured prompt
        prompt = self._build_prompt(findings, original_config, file_type)
        
        # Call LLM with retry logic
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                # Use requests to call OpenRouter API
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security expert analyzing infrastructure configurations. You must respond ONLY with valid JSON matching the specified schema. Do not include markdown code blocks or any text outside the JSON object."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "temperature": 0.3,
                        "max_tokens": 3000
                    },
                    timeout=60
                )
                
                if response.status_code != 200:
                    raise Exception(f"API error: {response.status_code} - {response.text}")
                
                response_data = response.json()
                response_text = response_data['choices'][0]['message']['content'].strip()
                
                # Clean response (remove markdown if present)
                response_text = re.sub(r'^```json\s*', '', response_text)
                response_text = re.sub(r'\s*```$', '', response_text)
                response_text = response_text.strip()
                
                # Parse and validate JSON
                result = json.loads(response_text)
                
                # Validate schema
                if self._validate_schema(result):
                    return result
                else:
                    if attempt == max_attempts - 1:
                        raise ValueError("Invalid response schema after max attempts")
            
            except json.JSONDecodeError as e:
                if attempt == max_attempts - 1:
                    return self._fallback_response(findings, original_config)
            
            except Exception as e:
                if attempt == max_attempts - 1:
                    print(f"AI Analysis error: {e}")
                    return self._fallback_response(findings, original_config)
        
        return self._fallback_response(findings, original_config)
    
    def _build_prompt(self, findings: List[Dict], original_config: str, 
                     file_type: str) -> str:
        """Construct deterministic prompt template."""
        
        findings_json = json.dumps(findings, indent=2)
        
        # Truncate config if too long
        config_preview = original_config[:2000] if len(original_config) > 2000 else original_config
        
        prompt = f"""You are analyzing a {file_type} configuration file for security and deployment risks.

FINDINGS FROM STATIC ANALYSIS:
{findings_json}

ORIGINAL CONFIGURATION:
```
{config_preview}
```

Your task is to provide a comprehensive security analysis. You MUST respond with ONLY a JSON object (no markdown, no explanations outside JSON) with this EXACT structure:

{{
  "diagnosis": "A clear, concise plain-language explanation of what security issues were found and their business impact. 2-4 sentences.",
  "severity_justification": "Explain why these findings matter and justify the overall risk score. Consider potential attack vectors and business consequences. 2-3 sentences.",
  "remediation_steps": [
    "Step 1: Specific action to fix issue X",
    "Step 2: Specific action to fix issue Y",
    "Step 3: Additional hardening recommendation"
  ],
  "improved_config": "The complete, corrected configuration file with all security issues fixed. Must be valid {file_type} syntax.",
  "overall_risk_score": 75
}}

RULES:
1. diagnosis: Plain language summary of issues found
2. severity_justification: Explain the risk level
3. remediation_steps: Array of 3-7 specific action items
4. improved_config: Full corrected configuration (not a diff)
5. overall_risk_score: Integer 0-100 (0=no risk, 100=critical)

Calculate risk score based on:
- CRITICAL findings: +30 points each
- HIGH findings: +20 points each  
- MEDIUM findings: +10 points each
- LOW findings: +5 points each
- Cap at 100

Respond with ONLY the JSON object. No other text."""

        return prompt
    
    def _validate_schema(self, result: Dict) -> bool:
        """Validate LLM response matches expected schema."""
        required_keys = [
            'diagnosis',
            'severity_justification', 
            'remediation_steps',
            'improved_config',
            'overall_risk_score'
        ]
        
        if not all(key in result for key in required_keys):
            return False
        
        if not isinstance(result['remediation_steps'], list):
            return False
        
        if not isinstance(result['overall_risk_score'], (int, float)):
            return False
        
        if not 0 <= result['overall_risk_score'] <= 100:
            return False
        
        return True
    
    def _fallback_response(self, findings: List[Dict], 
                          original_config: str) -> Dict[str, Any]:
        """Generate fallback response if LLM fails."""
        
        # Calculate basic risk score
        risk_score = 0
        for finding in findings:
            severity = finding.get('severity_guess', 'LOW')
            if severity == Config.SEVERITY_CRITICAL:
                risk_score += 30
            elif severity == Config.SEVERITY_HIGH:
                risk_score += 20
            elif severity == Config.SEVERITY_MEDIUM:
                risk_score += 10
            else:
                risk_score += 5
        
        risk_score = min(risk_score, 100)
        
        # Generate basic remediation steps
        remediation_steps = []
        seen_categories = set()
        
        for finding in findings[:5]:  # Top 5 findings
            category = finding.get('rule_category', 'Unknown')
            if category not in seen_categories:
                remediation_steps.append(
                    f"Address {category} issue: {finding.get('description', 'Unknown issue')}"
                )
                seen_categories.add(category)
        
        return {
            'diagnosis': f'Static analysis detected {len(findings)} security issues across multiple categories. Manual review recommended.',
            'severity_justification': f'Risk score of {risk_score} based on finding severity distribution. Immediate action required for critical findings.',
            'remediation_steps': remediation_steps if remediation_steps else ['Review all findings and apply fixes manually'],
            'improved_config': original_config + '\n\n# NOTE: LLM analysis unavailable. Please review findings manually.',
            'overall_risk_score': risk_score
        }
    
    def generate_diff(self, original: str, improved: str) -> str:
        """Generate unified diff between original and improved configs."""
        import difflib
        
        original_lines = original.splitlines(keepends=True)
        improved_lines = improved.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            improved_lines,
            fromfile='original',
            tofile='improved',
            lineterm=''
        )
        
        return ''.join(diff)