import { Server, ShieldCheck, KeyRound, GitBranch, FlaskConical, CheckCircle2, Terminal, FileWarning } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const CopyBlock = ({ code }: { code: string }) => (
  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 overflow-x-auto text-xs font-mono text-slate-300 whitespace-pre">
    {code}
  </pre>
);

export function DeploymentGuide() {
  return (
    <div className="pt-8 space-y-6">
      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
              <Terminal className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <CardTitle className="text-slate-50 text-xl font-serif">Deployment & Testing Guide</CardTitle>
              <CardDescription className="text-slate-500">
                Ubuntu 24.04 LTS · mTLS · Corporate Environment · Phase 1 (Pre-OIDC)
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline" className="border-emerald-500/30 text-emerald-400 bg-emerald-500/10">Phase 1: MVP Testing</Badge>
            <Badge variant="outline" className="border-slate-700 text-slate-400 bg-slate-800/50">Phase 2: OIDC + Org Checks</Badge>
            <Badge variant="outline" className="border-slate-700 text-slate-400 bg-slate-800/50">Python FastAPI Backend</Badge>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <span className="h-6 w-6 rounded-md bg-slate-800 border border-slate-700 text-emerald-400 text-xs font-mono flex items-center justify-center">1</span>
            <Server className="h-4 w-4 text-sky-400" />
            Install System Dependencies
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-400">Update package lists and install required security tools on the Ubuntu 24.04 VM.</p>
          <CopyBlock code={`# Update system packages
sudo apt update && sudo apt upgrade -y

# Install core dependencies
sudo apt install -y git python3 python3-pip python3-venv docker.io curl

# Install Trivy (SCA)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
sudo mv trivy /usr/local/bin/

# Install Bandit (Python Static Analysis)
pip3 install bandit

# Install Megalinter
pip3 install megalinter`} />
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <span className="h-6 w-6 rounded-md bg-slate-800 border border-slate-700 text-emerald-400 text-xs font-mono flex items-center justify-center">2</span>
            <KeyRound className="h-4 w-4 text-amber-400" />
            Secure OpenAI API Key Storage
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-400">
            Never hardcode secrets. Use environment variables or a secrets manager like HashiCorp Vault. For this test, we use a secure environment file.
          </p>
          <CopyBlock code={`# Create a secure environment file
sudo nano /etc/reposentinel/.env

# Add your OpenAI API key securely
OPENAI_API_KEY=sk-your-secure-key-here
OPENAI_MODEL=gpt-4o

# Lock down permissions
sudo chown root:root /etc/reposentinel/.env
sudo chmod 600 /etc/reposentinel/.env`} />
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <span className="h-6 w-6 rounded-md bg-slate-800 border border-slate-700 text-emerald-400 text-xs font-mono flex items-center justify-center">3</span>
            <GitBranch className="h-4 w-4 text-violet-400" />
            Backend Setup (FastAPI)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-400">Create a Python virtual environment and install the backend requirements.</p>
          <CopyBlock code={`# Clone the backend repository (or upload your code)
git clone https://github.com/your-org/reposentinel-backend.git
cd reposentinel-backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Required Python packages:
# fastapi uvicorn openai python-dotenv gitpython pyyaml jinja2`} />
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <span className="h-6 w-6 rounded-md bg-slate-800 border border-slate-700 text-emerald-400 text-xs font-mono flex items-center justify-center">4</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            mTLS Configuration & IP Allowlisting
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-400">
            Generate internal CA and client certificates for mutual TLS. Restrict access to the corporate IP range (e.g., 10.0.0.0/8).
          </p>
          <CopyBlock code={`# Generate self-signed CA and certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \\
  -subj "/CN=Corp Internal CA"

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \\
  -subj "/CN=reposentinel.corp"
openssl x509 -req -days 365 -in server.csr -CA ca.crt \\
  -CAkey ca.key -CAcreateserial -out server.crt

# Run Uvicorn with SSL and require client certs
uvicorn main:app --host 0.0.0.0 --port 8443 \\
  --ssl-certfile server.crt \\
  --ssl-keyfile server.key \\
  --ssl-ca-file ca.crt \\
  --ssl-cert-reqs 1`} />
          <div className="flex items-start gap-2 text-sm text-amber-400 bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 mt-3">
            <FileWarning className="h-4 w-4 mt-0.5 shrink-0" />
            <span>Ensure your corporate firewall or cloud security group only allows inbound traffic to port 8443 from the 10.0.0.0/8 IP range.</span>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <span className="h-6 w-6 rounded-md bg-slate-800 border border-slate-700 text-emerald-400 text-xs font-mono flex items-center justify-center">5</span>
            <FlaskConical className="h-4 w-4 text-rose-400" />
            Testing the Deployment
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-400">Test the mTLS connection and analysis pipeline from an authorized corporate machine.</p>
          <CopyBlock code={`# 1. Test basic connectivity (should return mTLS error without cert)
curl https://reposentinel.corp:8443/health

# 2. Test with client certificate
curl --cert client.crt --key client.key \\
  --cacert ca.crt https://reposentinel.corp:8443/health

# 3. Submit a test repository for analysis
curl -X POST --cert client.crt --key client.key \\
  --cacert ca.crt https://reposentinel.corp:8443/analyze \\
  -H "Content-Type: application/json" \\
  -d '{"repo_url": "https://github.com/your-org/test-repo"}'

# 4. Check analysis status
curl --cert client.crt --key client.key \\
  --cacert ca.crt https://reposentinel.corp:8443/status/analysis-123`} />
        </CardContent>
      </Card>

      <Card className="bg-slate-900 border-slate-800 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-slate-100 text-base flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            Phase 1 Validation Checklist
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2">
            {[
              "Backend VM is running Ubuntu 24.04 and all tools (Trivy, Bandit, Megalinter) are installed.",
              "OpenAI API key is stored in /etc/reposentinel/.env with 600 permissions.",
              "Uvicorn is running on port 8443 with mTLS enforced.",
              "Firewall rules restrict access to corporate IP range only.",
              "Repository URL validation rejects non-HTTPS and non-corporate hosts.",
              "Rate limiting prevents more than 1 submission per 60 seconds.",
              "HTML reports are generated and downloadable via the WebUI.",
              "Audit logs capture all actions (submission, tool execution, AI triage).",
            ].map((item, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-slate-300">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
