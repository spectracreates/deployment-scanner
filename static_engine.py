import yaml
import re
import hcl2
from typing import List, Dict, Any
from config import Config

class Finding:
    """Represents a single security finding."""
    
    def __init__(self, issue_id: str, description: str, location: str, 
                 severity_guess: str, snippet: str, rule_category: str):
        self.issue_id = issue_id
        self.description = description
        self.location = location
        self.severity_guess = severity_guess
        self.snippet = snippet
        self.rule_category = rule_category
    
    def to_dict(self) -> Dict[str, str]:
        return {
            'issue_id': self.issue_id,
            'description': self.description,
            'location': self.location,
            'severity_guess': self.severity_guess,
            'snippet': self.snippet,
            'rule_category': self.rule_category
        }

class StaticAnalyzer:
    """Main static analysis engine for infrastructure configs."""
    
    def __init__(self):
        self.findings: List[Finding] = []
    
    def analyze_file(self, filepath: str, content: str) -> List[Finding]:
        """Route to appropriate analyzer based on file type."""
        self.findings = []
        
        if filepath.endswith(('.yaml', '.yml')):
            self._analyze_kubernetes(content)
        elif filepath.endswith('.tf'):
            self._analyze_terraform(content)
        elif 'dockerfile' in filepath.lower():
            self._analyze_dockerfile(content)
        
        return self.findings
    
    def _analyze_kubernetes(self, content: str):
        """Analyze Kubernetes YAML manifests."""
        try:
            docs = list(yaml.safe_load_all(content))
            
            for idx, doc in enumerate(docs):
                if not doc or not isinstance(doc, dict):
                    continue
                
                kind = doc.get('kind', 'Unknown')
                metadata = doc.get('metadata', {})
                name = metadata.get('name', f'resource-{idx}')
                location = f"{kind}/{name}"
                
                # Check for Deployment/Pod specs
                if kind in ['Deployment', 'StatefulSet', 'DaemonSet', 'Pod']:
                    spec = doc.get('spec', {})
                    if kind != 'Pod':
                        template_spec = spec.get('template', {}).get('spec', {})
                    else:
                        template_spec = spec
                    
                    containers = template_spec.get('containers', [])
                    
                    for cidx, container in enumerate(containers):
                        cname = container.get('name', f'container-{cidx}')
                        clocation = f"{location}/containers[{cidx}]/{cname}"
                        
                        # Rule K1: Missing resource limits
                        resources = container.get('resources', {})
                        if not resources.get('limits'):
                            self.findings.append(Finding(
                                issue_id='K1',
                                description='Container has no resource limits defined',
                                location=clocation,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet=f"Container '{cname}' missing resources.limits",
                                rule_category='Resource Management'
                            ))
                        
                        # Rule K2: Missing resource requests
                        if not resources.get('requests'):
                            self.findings.append(Finding(
                                issue_id='K2',
                                description='Container has no resource requests defined',
                                location=clocation,
                                severity_guess=Config.SEVERITY_MEDIUM,
                                snippet=f"Container '{cname}' missing resources.requests",
                                rule_category='Resource Management'
                            ))
                        
                        # Rule K3: Missing readiness probe
                        if not container.get('readinessProbe'):
                            self.findings.append(Finding(
                                issue_id='K3',
                                description='Container has no readiness probe',
                                location=clocation,
                                severity_guess=Config.SEVERITY_MEDIUM,
                                snippet=f"Container '{cname}' missing readinessProbe",
                                rule_category='Health Checks'
                            ))
                        
                        # Rule K4: Missing liveness probe
                        if not container.get('livenessProbe'):
                            self.findings.append(Finding(
                                issue_id='K4',
                                description='Container has no liveness probe',
                                location=clocation,
                                severity_guess=Config.SEVERITY_MEDIUM,
                                snippet=f"Container '{cname}' missing livenessProbe",
                                rule_category='Health Checks'
                            ))
                        
                        # Rule K5: Privileged container
                        sec_context = container.get('securityContext', {})
                        if sec_context.get('privileged', False):
                            self.findings.append(Finding(
                                issue_id='K5',
                                description='Container runs in privileged mode',
                                location=clocation,
                                severity_guess=Config.SEVERITY_CRITICAL,
                                snippet=f"Container '{cname}' has privileged: true",
                                rule_category='Security'
                            ))
                        
                        # Rule K6: Running as root
                        if sec_context.get('runAsUser') == 0:
                            self.findings.append(Finding(
                                issue_id='K6',
                                description='Container runs as root user (UID 0)',
                                location=clocation,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet=f"Container '{cname}' has runAsUser: 0",
                                rule_category='Security'
                            ))
                        
                        # Rule K7: Host network mode
                        if template_spec.get('hostNetwork', False):
                            self.findings.append(Finding(
                                issue_id='K7',
                                description='Pod uses host network namespace',
                                location=location,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet='hostNetwork: true',
                                rule_category='Security'
                            ))
                        
                        # Rule K8: Host PID mode
                        if template_spec.get('hostPID', False):
                            self.findings.append(Finding(
                                issue_id='K8',
                                description='Pod uses host PID namespace',
                                location=location,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet='hostPID: true',
                                rule_category='Security'
                            ))
                        
                        # Rule K9: Image pull policy not Always
                        pull_policy = container.get('imagePullPolicy', '')
                        if pull_policy != 'Always' and not container.get('image', '').endswith(':latest'):
                            self.findings.append(Finding(
                                issue_id='K9',
                                description='Image pull policy should be Always for non-latest tags',
                                location=clocation,
                                severity_guess=Config.SEVERITY_LOW,
                                snippet=f"imagePullPolicy: {pull_policy}",
                                rule_category='Image Management'
                            ))
                        
                        # Rule K10: Using latest tag
                        image = container.get('image', '')
                        if ':latest' in image or ':' not in image:
                            self.findings.append(Finding(
                                issue_id='K10',
                                description='Image uses latest tag or no tag specified',
                                location=clocation,
                                severity_guess=Config.SEVERITY_MEDIUM,
                                snippet=f"image: {image}",
                                rule_category='Image Management'
                            ))
                
                # Check for Service exposures
                if kind == 'Service':
                    spec = doc.get('spec', {})
                    service_type = spec.get('type', 'ClusterIP')
                    
                    # Rule K11: LoadBalancer without restrictions
                    if service_type == 'LoadBalancer':
                        load_balancer_ips = spec.get('loadBalancerSourceRanges', [])
                        if not load_balancer_ips:
                            self.findings.append(Finding(
                                issue_id='K11',
                                description='LoadBalancer service has no source IP restrictions',
                                location=location,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet='type: LoadBalancer without loadBalancerSourceRanges',
                                rule_category='Network Security'
                            ))
                
                # Check for Ingress
                if kind == 'Ingress':
                    spec = doc.get('spec', {})
                    
                    # Rule K12: No TLS configuration
                    if not spec.get('tls'):
                        self.findings.append(Finding(
                            issue_id='K12',
                            description='Ingress has no TLS configuration',
                            location=location,
                            severity_guess=Config.SEVERITY_HIGH,
                            snippet='Missing spec.tls section',
                            rule_category='Network Security'
                        ))
                
                # Check for ConfigMap/Secret
                if kind in ['ConfigMap', 'Secret']:
                    data = doc.get('data', {})
                    
                    # Rule K13: Potential credentials in ConfigMap
                    if kind == 'ConfigMap':
                        for key, value in data.items():
                            if any(word in key.lower() for word in ['password', 'secret', 'key', 'token', 'credential']):
                                self.findings.append(Finding(
                                    issue_id='K13',
                                    description=f'Potential credential stored in ConfigMap: {key}',
                                    location=f"{location}/data/{key}",
                                    severity_guess=Config.SEVERITY_CRITICAL,
                                    snippet=f'ConfigMap contains key: {key}',
                                    rule_category='Secrets Management'
                                ))
        
        except yaml.YAMLError as e:
            self.findings.append(Finding(
                issue_id='PARSE_ERROR',
                description=f'YAML parsing error: {str(e)}',
                location='file',
                severity_guess=Config.SEVERITY_CRITICAL,
                snippet=str(e),
                rule_category='Syntax'
            ))
    
    def _analyze_terraform(self, content: str):
        """Analyze Terraform configurations."""
        try:
            # Parse HCL
            tf_dict = hcl2.loads(content)
            
            # Check for AWS Security Groups
            resources = tf_dict.get('resource', [{}])[0] if tf_dict.get('resource') else {}
            
            for resource_type, resource_configs in resources.items():
                for resource_name, resource_config in resource_configs.items():
                    location = f"{resource_type}.{resource_name}"
                    
                    # Rule T1: Open security group ingress
                    if resource_type == 'aws_security_group':
                        ingress_rules = resource_config.get('ingress', [])
                        for idx, rule in enumerate(ingress_rules):
                            cidr_blocks = rule.get('cidr_blocks', [])
                            if '0.0.0.0/0' in cidr_blocks or '::/0' in cidr_blocks:
                                from_port = rule.get('from_port', 0)
                                to_port = rule.get('to_port', 0)
                                
                                self.findings.append(Finding(
                                    issue_id='T1',
                                    description=f'Security group allows ingress from 0.0.0.0/0 on ports {from_port}-{to_port}',
                                    location=f"{location}/ingress[{idx}]",
                                    severity_guess=Config.SEVERITY_CRITICAL if from_port <= 22 <= to_port or from_port <= 3389 <= to_port else Config.SEVERITY_HIGH,
                                    snippet=f'cidr_blocks = ["0.0.0.0/0"]',
                                    rule_category='Network Security'
                                ))
                    
                    # Rule T2: S3 bucket public access
                    if resource_type == 'aws_s3_bucket_public_access_block':
                        if not resource_config.get('block_public_acls', False):
                            self.findings.append(Finding(
                                issue_id='T2',
                                description='S3 bucket does not block public ACLs',
                                location=location,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet='block_public_acls = false or missing',
                                rule_category='Data Security'
                            ))
                    
                    # Rule T3: Unencrypted EBS volume
                    if resource_type == 'aws_ebs_volume':
                        if not resource_config.get('encrypted', False):
                            self.findings.append(Finding(
                                issue_id='T3',
                                description='EBS volume is not encrypted',
                                location=location,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet='encrypted = false or missing',
                                rule_category='Data Security'
                            ))
                    
                    # Rule T4: RDS without encryption
                    if resource_type == 'aws_db_instance':
                        if not resource_config.get('storage_encrypted', False):
                            self.findings.append(Finding(
                                issue_id='T4',
                                description='RDS instance storage is not encrypted',
                                location=location,
                                severity_guess=Config.SEVERITY_HIGH,
                                snippet='storage_encrypted = false or missing',
                                rule_category='Data Security'
                            ))
                    
                    # Rule T5: Hardcoded credentials
                    config_str = str(resource_config)
                    if re.search(r'(password|secret|key)\s*=\s*["\'][^"\']+["\']', config_str, re.IGNORECASE):
                        self.findings.append(Finding(
                            issue_id='T5',
                            description='Potential hardcoded credentials detected',
                            location=location,
                            severity_guess=Config.SEVERITY_CRITICAL,
                            snippet='Hardcoded password/secret/key found',
                            rule_category='Secrets Management'
                        ))
        
        except Exception as e:
            self.findings.append(Finding(
                issue_id='PARSE_ERROR',
                description=f'Terraform parsing error: {str(e)}',
                location='file',
                severity_guess=Config.SEVERITY_CRITICAL,
                snippet=str(e),
                rule_category='Syntax'
            ))
    
    def _analyze_dockerfile(self, content: str):
        """Analyze Dockerfiles."""
        lines = content.split('\n')
        
        for idx, line in enumerate(lines, 1):
            line = line.strip()
            location = f"line {idx}"
            
            # Rule D1: Using latest tag
            if line.upper().startswith('FROM') and ':latest' in line:
                self.findings.append(Finding(
                    issue_id='D1',
                    description='Base image uses latest tag',
                    location=location,
                    severity_guess=Config.SEVERITY_MEDIUM,
                    snippet=line,
                    rule_category='Image Management'
                ))
            
            # Rule D2: Running as root (no USER directive)
            if idx == len(lines) and not any('USER' in l.upper() for l in lines):
                self.findings.append(Finding(
                    issue_id='D2',
                    description='Dockerfile does not specify non-root USER',
                    location='end of file',
                    severity_guess=Config.SEVERITY_HIGH,
                    snippet='No USER directive found',
                    rule_category='Security'
                ))
            
            # Rule D3: ADD instead of COPY
            if line.upper().startswith('ADD') and not line.endswith(('.tar', '.tar.gz', '.tgz', '.zip')):
                self.findings.append(Finding(
                    issue_id='D3',
                    description='Using ADD instead of COPY for non-archive files',
                    location=location,
                    severity_guess=Config.SEVERITY_LOW,
                    snippet=line,
                    rule_category='Best Practices'
                ))
            
            # Rule D4: Exposed privileged ports
            if line.upper().startswith('EXPOSE'):
                ports = re.findall(r'\d+', line)
                for port in ports:
                    if int(port) < 1024:
                        self.findings.append(Finding(
                            issue_id='D4',
                            description=f'Exposing privileged port {port}',
                            location=location,
                            severity_guess=Config.SEVERITY_MEDIUM,
                            snippet=line,
                            rule_category='Security'
                        ))
            
            # Rule D5: Hardcoded secrets
            if re.search(r'(PASSWORD|SECRET|KEY|TOKEN)=[^\s]+', line, re.IGNORECASE):
                self.findings.append(Finding(
                    issue_id='D5',
                    description='Potential hardcoded secret in Dockerfile',
                    location=location,
                    severity_guess=Config.SEVERITY_CRITICAL,
                    snippet=line[:50] + '...' if len(line) > 50 else line,
                    rule_category='Secrets Management'
                ))
            
            # Rule D6: Using sudo
            if 'sudo' in line.lower():
                self.findings.append(Finding(
                    issue_id='D6',
                    description='Using sudo in Dockerfile',
                    location=location,
                    severity_guess=Config.SEVERITY_LOW,
                    snippet=line,
                    rule_category='Best Practices'
                ))
            
            # Rule D7: HEALTHCHECK missing
            if idx == len(lines) and not any('HEALTHCHECK' in l.upper() for l in lines):
                self.findings.append(Finding(
                    issue_id='D7',
                    description='No HEALTHCHECK instruction defined',
                    location='end of file',
                    severity_guess=Config.SEVERITY_MEDIUM,
                    snippet='Missing HEALTHCHECK',
                    rule_category='Health Checks'
                ))