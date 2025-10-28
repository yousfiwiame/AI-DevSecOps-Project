// Dashboard JavaScript
let vulnerabilities = [];
let policies = [];

// Load vulnerabilities on page load
document.addEventListener('DOMContentLoaded', function() {
    loadVulnerabilities();
    loadPolicies();
});

async function loadVulnerabilities() {
    try {
        const response = await fetch('/api/vulnerabilities');
        vulnerabilities = await response.json();
        displayVulnerabilities();
        updateStats();
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
    }
}

function displayVulnerabilities() {
    const container = document.getElementById('vulnerabilitiesList');
    
    if (vulnerabilities.length === 0) {
        container.innerHTML = '<div class="empty-state">No vulnerabilities detected</div>';
        return;
    }
    
    container.innerHTML = vulnerabilities.map(vuln => `
        <div class="vulnerability-item ${vuln.severity.toLowerCase()}" data-id="${vuln.id}">
            <div class="vulnerability-header">
                <div>
                    <div class="vulnerability-title">${vuln.type}</div>
                    <div class="vulnerability-meta">
                        <span>Source: ${vuln.source}</span>
                        <span>Tool: ${vuln.tool}</span>
                        <span>CWE: ${vuln.cwe}</span>
                    </div>
                </div>
                <span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            </div>
            <p style="margin-top: 10px; color: #64748b;"><strong>Description:</strong> ${vuln.description}</p>
            <p style="margin-top: 5px; color: #64748b;"><strong>Remediation:</strong> ${vuln.remediation}</p>
            <p style="margin-top: 5px; font-size: 0.9rem; color: #94a3b8;"><em>Location: ${vuln.location}</em></p>
        </div>
    `).join('');
}

function updateStats() {
    const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const totalCount = vulnerabilities.length;
    
    document.getElementById('highCount').textContent = highCount;
    document.getElementById('mediumCount').textContent = mediumCount;
    document.getElementById('totalCount').textContent = totalCount;
    document.getElementById('policyCount').textContent = policies.length;
}

function loadPolicies() {
    const policiesStr = localStorage.getItem('generatedPolicies');
    if (policiesStr) {
        policies = JSON.parse(policiesStr);
    }
    displayPolicies();
}

function displayPolicies() {
    const container = document.getElementById('policiesList');
    
    if (policies.length === 0) {
        container.innerHTML = '<div class="empty-state">No policies generated yet. Click "Generate Security Policy" to create one.</div>';
        return;
    }
    
    container.innerHTML = policies.slice().reverse().map((policy, idx) => `
        <div class="vulnerability-item" style="border-left-color: #6366f1;">
            <div class="vulnerability-header">
                <div>
                    <div class="vulnerability-title">Policy Generated - ${new Date(policy.timestamp).toLocaleString()}</div>
                    <div class="vulnerability-meta">
                        <span>Model: ${policy.model}</span>
                        <span>Vulnerabilities: ${policy.vulnerabilityCount}</span>
                    </div>
                </div>
            </div>
            <button class="btn btn-primary" style="margin-top: 10px;" onclick="viewPolicy(${policies.length - 1 - idx})">View Policy</button>
        </div>
    `).join('');
}

function generatePolicy() {
    if (vulnerabilities.length === 0) {
        alert('No vulnerabilities to generate policy from');
        return;
    }
    
    const modal = document.getElementById('policyModal');
    modal.classList.add('show');
    
    const policyContent = document.getElementById('policyContent');
    policyContent.innerHTML = '<div class="loading">Generating policy...</div>';
    
    // Simulate API call to generate policy
    setTimeout(() => {
        const policy = {
            content: generatePolicyContent(),
            timestamp: new Date().toISOString(),
            model: 'GPT-4',
            vulnerabilityCount: vulnerabilities.length
        };
        
        policies.push(policy);
        localStorage.setItem('generatedPolicies', JSON.stringify(policies));
        
        displayPolicyContent(policy);
        displayPolicies();
    }, 2000);
}

function generatePolicyContent() {
    const highVulns = vulnerabilities.filter(v => v.severity === 'HIGH');
    const mediumVulns = vulnerabilities.filter(v => v.severity === 'MEDIUM');
    
    return `
        <h3>Security Policy Document</h3>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
        
        <h4>1. Executive Summary</h4>
        <p>This security policy addresses ${vulnerabilities.length} identified vulnerabilities across the application, 
        including ${highVulns.length} high-severity and ${mediumVulns.length} medium-severity issues. 
        The policy aligns with NIST Cybersecurity Framework and ISO/IEC 27001 standards.</p>
        
        <h4>2. Policy Scope</h4>
        <p>This policy applies to all components of the application, including authentication, data processing, 
        and user input handling modules.</p>
        
        <h4>3. Risk Assessment</h4>
        <p>Based on vulnerability analysis:</p>
        <ul>
            ${highVulns.map(v => `<li><strong>${v.type}:</strong> ${v.description}</li>`).join('')}
        </ul>
        
        <h4>4. Security Controls</h4>
        <p>In accordance with NIST CSF and ISO 27001:</p>
        <ul>
            ${vulnerabilities.map(v => `<li>Implement ${v.remediation} to address ${v.type}</li>`).join('')}
        </ul>
        
        <h4>5. Implementation Guidelines</h4>
        <p>All identified vulnerabilities must be addressed within 30 days. Code reviews and security testing 
        shall be conducted prior to production deployment.</p>
        
        <h4>6. Compliance Requirements</h4>
        <p>This policy ensures compliance with:</p>
        <ul>
            <li>NIST CSF Function: Protect</li>
            <li>ISO 27001 Control: A.12.6.1 Management of technical vulnerabilities</li>
            <li>OWASP Top 10 security risks</li>
        </ul>
    `;
}

function displayPolicyContent(policy) {
    document.getElementById('policyContent').innerHTML = `
        <div style="padding: 20px; background: #f8fafc; border-radius: 8px;">
            ${policy.content}
        </div>
    `;
}

function viewPolicy(index) {
    const modal = document.getElementById('policyModal');
    modal.classList.add('show');
    displayPolicyContent(policies[index]);
}

function closeModal() {
    document.getElementById('policyModal').classList.remove('show');
}

function downloadPolicy() {
    alert('Download functionality would be implemented here');
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('policyModal');
    if (event.target === modal) {
        closeModal();
    }
}

