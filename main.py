# main.py -Entry point
# Automatically loads every check module found in the checks/ folder.
# To add a new misconfiguration check, just drop a new file into checks
# https://www.chartjs.org/docs/latest/charts/bar.html Used For bar Chart
# https://www.chartjs.org/docs/latest/charts/doughnut.html used for Pie chart
import yaml
import sys
import os
import importlib
import argparse
from datetime import datetime

CHECKS_DIR = os.path.join(os.path.dirname(__file__), "checks")
def load_checks() -> list:
#Scan the checks/ directory and import every module that has a run() function. Returns a list of imported modules.
    check_modules = []
 
    for filename in sorted(os.listdir(CHECKS_DIR)):
        if filename.startswith("_") or not filename.endswith(".py"):
            continue
        module_name = f"checks.{filename[:-3]}"
        try:
            module = importlib.import_module(module_name)
            if callable(getattr(module, "run", None)):
                check_modules.append(module)
        except Exception as e:
            print(f"[WARN] Could not load check module '{module_name}': {e}")
 
    return check_modules

def load_compose_file(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def scan_file(path: str, checks: list) -> list[dict]:
#Runs all checks against a single compose file. Each finding is tagged with the check name it came from. 
    try:
        compose = load_compose_file(path)
    except Exception as e:
        print(f"  [ERROR] Could not parse {path}: {e}")
        return []
 
    all_findings = []
    for check in checks:
        findings = check.run(compose)
        for f in findings:
            f["check"] = getattr(check, "CHECK_NAME", check.__name__)
        all_findings.extend(findings)
 
    return all_findings
# terminal output
def print_findings(findings: list[dict]) -> None:
    for f in findings:
        print(f"  Check    : {f.get('check', 'Unknown')}")
        print(f"  Severity : {f['severity']}")
        print(f"  Service  : {f['service']}")
        print(f"  Value    : {f.get('value', '')}")
        print(f"  Detail   : {f['detail']}")
        print(f"  Fix      : {f['fix']}")
        print()
 
 
# HTML report
 
def build_html_report(scan_results, checks, path):
    timestamp = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    checks_loaded = ", ".join(getattr(c, "CHECK_NAME", c.__name__) for c in checks)
    total_files = len(scan_results)
    files_with_issues = sum(1 for r in scan_results if r["findings"])
    # build findings tab rows
    rows = ""
    for result in scan_results:
        filename = result["filename"]
        findings = result["findings"]
        if findings:
            rows += f'<div class="file warning" data-file="{filename}">\n'
            rows += f'  <div class="file-header">WARNING [{filename}]</div>\n'
            for f in findings:
                rows += f'  <div class="finding">\n'
                rows += f'    <div class="finding-row"><span class="label">Check    :</span> {f.get("check", "Unknown")}</div>\n'
                rows += f'    <div class="finding-row"><span class="label">Severity :</span> <span class="sev-{f["severity"].lower()}">{f["severity"]}</span></div>\n'
                rows += f'    <div class="finding-row"><span class="label">Service  :</span> {f["service"]}</div>\n'
                rows += f'    <div class="finding-row"><span class="label">Value    :</span> {f.get("value", "")}</div>\n'
                rows += f'    <div class="finding-row"><span class="label">Detail   :</span> {f["detail"]}</div>\n'
                rows += f'    <div class="finding-row"><span class="label">Fix      :</span> {f["fix"]}</div>\n'
                rows += f'  </div>\n'
            rows += '</div>\n'
        else:
            rows += f'<div class="file ok" data-file="{filename}">\n'
            rows += f'  <div class="file-header">OK &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [{filename}]: no issues found</div>\n'
            rows += '</div>\n'
    # build json data for charts from chartsjs
    import json
    scan_json = json.dumps(scan_results)
    filenames_json = json.dumps([r["filename"] for r in scan_results])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Static Docker Analyser - Report</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    body        {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 2rem; }}
    h1          {{ color: #ffffff; font-size: 1.2rem; margin-bottom: 0.2rem; }}
    .meta       {{ color: #888; font-size: 0.85rem; margin-bottom: 1rem; }}
    .tabs       {{ display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }}
    .tab-btn    {{ background: #252525; color: #888; border: 1px solid #444; padding: 0.4rem 1.2rem; cursor: pointer; font-family: monospace; font-size: 0.9rem; }}
    .tab-btn.active {{ background: #1e1e1e; color: #fff; border-bottom-color: #1e1e1e; border-top: 2px solid #4fc1ff; }}
    .tab-panel  {{ display: none; }}
    .tab-panel.active {{ display: block; }}
    .file       {{ margin-bottom: 1rem; padding: 0.8rem 1rem; border-left: 4px solid #444; background: #252525; }}
    .file.warning {{ border-left-color: #e5a00d; }}
    .file.ok    {{ border-left-color: #4caf50; }}
    .file-header {{ font-weight: bold; margin-bottom: 0.5rem; }}
    .file.warning .file-header {{ color: #e5a00d; }}
    .file.ok .file-header {{ color: #4caf50; }}
    .finding    {{ margin: 0.6rem 0 0.6rem 1rem; padding: 0.5rem; border-left: 2px solid #333; }}
    .finding-row {{ margin: 0.15rem 0; }}
    .label      {{ color: #888; display: inline-block; width: 90px; }}
    .sev-high   {{ color: #f44747; font-weight: bold; }}
    .sev-medium {{ color: #e5a00d; font-weight: bold; }}
    .sev-low    {{ color: #4fc1ff; font-weight: bold; }}
    .sev-review {{ color: #c586c0; font-weight: bold; }}
    .summary-box {{ margin-top: 2rem; padding: 0.8rem 1rem; background: #252525; border-left: 4px solid #888; }}
    .summary-box h2 {{ font-size: 1rem; margin: 0 0 0.4rem 0; color: #fff; }}
    .filter-bar {{ margin-bottom: 1.5rem; }}
    .filter-bar label {{ color: #888; margin-right: 0.5rem; }}
    .filter-bar select {{ background: #252525; color: #d4d4d4; border: 1px solid #444; padding: 0.3rem 0.6rem; font-family: monospace; font-size: 0.9rem; cursor: pointer; }}
    .charts-row {{ display: flex; gap: 2rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .chart-box  {{ background: #252525; padding: 1rem; flex: 1; min-width: 300px; }}
    .chart-box h3 {{ color: #fff; font-size: 0.95rem; margin: 0 0 0.8rem 0; }}
    .service-list {{ background: #252525; padding: 1rem; }}
    .service-list h3 {{ color: #fff; font-size: 0.95rem; margin: 0 0 0.8rem 0; }}
    .svc-row    {{ margin-bottom: 0.6rem; padding-bottom: 0.6rem; border-bottom: 1px solid #333; }}
    .svc-name   {{ color: #4fc1ff; margin-bottom: 0.2rem; }}
    .svc-tag    {{ display: inline-block; margin: 0.1rem 0.2rem 0.1rem 0; padding: 0.1rem 0.4rem; font-size: 0.8rem; background: #1e1e1e; border: 1px solid #444; }}
    canvas      {{ max-height: 300px; }}
  </style>
</head>
<body>
  <h1>Static Docker Analyser</h1>
  <div class="meta">
    Report generated : {timestamp}<br>
    Path scanned     : {path}<br>
    Checks loaded    : {checks_loaded}
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('findings')">Findings</button>
    <button class="tab-btn" onclick="switchTab('summary')">Summary</button>
  </div>

  <!-- FINDINGS TAB -->
  <div id="tab-findings" class="tab-panel active">
    {rows}
    <div class="summary-box">
      <h2>--- Summary ---</h2>
      <div>Files scanned &nbsp;&nbsp;&nbsp;&nbsp; : {total_files}</div>
      <div>Files with issues : {files_with_issues}</div>
    </div>
  </div>

  <!-- SUMMARY TAB -->
  <div id="tab-summary" class="tab-panel">
    <div class="filter-bar">
      <label>Filter by file:</label>
      <select id="file-filter" onchange="updateSummary()">
        <option value="__all__">All Files</option>
      </select>
    </div>
    <div class="charts-row">
      <div class="chart-box">
        <h3>Misconfigurations by Type</h3>
        <canvas id="barChart"></canvas>
      </div>
      <div class="chart-box">
        <h3>Findings by Severity</h3>
        <canvas id="pieChart"></canvas>
      </div>
    </div>
    <div class="service-list">
      <h3>Misconfigurations per Service</h3>
      <div id="service-breakdown"></div>
    </div>
  </div>

  <script>
    const scanData = {scan_json};
    const allFilenames = {filenames_json};

    // populate file filter dropdown
    const sel = document.getElementById("file-filter");
    allFilenames.forEach(fn => {{
      const opt = document.createElement("option");
      opt.value = fn;
      opt.textContent = fn;
      sel.appendChild(opt);
    }});

    let barChart, pieChart;

    function switchTab(name) {{
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.getElementById("tab-" + name).classList.add("active");
      event.target.classList.add("active");
      if (name === "summary") updateSummary();
    }}

    function getFilteredFindings() {{
      const selected = document.getElementById("file-filter").value;
      let findings = [];
      scanData.forEach(result => {{
        if (selected === "__all__" || result.filename === selected) {{
          result.findings.forEach(f => findings.push(f));
        }}
      }});
      return findings;
    }}

    function updateSummary() {{
      const findings = getFilteredFindings();

      // count by check type
      const checkCounts = {{}};
      findings.forEach(f => {{
        const name = f.check || "Unknown";
        checkCounts[name] = (checkCounts[name] || 0) + 1;
      }});

      // count by severity
      const sevCounts = {{ HIGH: 0, MEDIUM: 0, LOW: 0, REVIEW: 0 }};
      findings.forEach(f => {{
        const s = f.severity || "UNKNOWN";
        if (sevCounts[s] !== undefined) sevCounts[s]++;
        else sevCounts[s] = 1;
      }});

      // bar chart
      const barLabels = Object.keys(checkCounts);
      const barData = Object.values(checkCounts);
      if (barChart) barChart.destroy();
      barChart = new Chart(document.getElementById("barChart"), {{
        type: "bar",
        data: {{
          labels: barLabels,
          datasets: [{{ label: "Count", data: barData,
            backgroundColor: "#4fc1ff", borderColor: "#4fc1ff", borderWidth: 1 }}]
        }},
        options: {{
          indexAxis: "y",
          responsive: true,
          plugins: {{ legend: {{ display: false }} }},
          scales: {{
            x: {{ ticks: {{ color: "#888" }}, grid: {{ color: "#333" }} }},
            y: {{ ticks: {{ color: "#d4d4d4" }}, grid: {{ color: "#333" }} }}
          }}
        }}
      }});

      // pie chart
      const sevColors = {{ HIGH: "#f44747", MEDIUM: "#e5a00d", LOW: "#4fc1ff", REVIEW: "#c586c0" }};
      const pieLabels = Object.keys(sevCounts).filter(k => sevCounts[k] > 0);
      const pieData = pieLabels.map(k => sevCounts[k]);
      const pieColors = pieLabels.map(k => sevColors[k] || "#888");
      if (pieChart) pieChart.destroy();
      pieChart = new Chart(document.getElementById("pieChart"), {{
        type: "pie",
        data: {{
          labels: pieLabels,
          datasets: [{{ data: pieData, backgroundColor: pieColors, borderColor: "#1e1e1e", borderWidth: 2 }}]
        }},
        options: {{
          responsive: true,
          plugins: {{ legend: {{ labels: {{ color: "#d4d4d4" }} }} }}
        }}
      }});

      // per service breakdown
      const selected = document.getElementById("file-filter").value;
      const serviceCounts = {{}};
      scanData.forEach(result => {{
        if (selected === "__all__" || result.filename === selected) {{
          result.findings.forEach(f => {{
            const key = (selected === "__all__" ? result.filename + " > " : "") + f.service;
            if (!serviceCounts[key]) serviceCounts[key] = {{}};
            const check = f.check || "Unknown";
            serviceCounts[key][check] = (serviceCounts[key][check] || 0) + 1;
          }});
        }}
      }});

      const el = document.getElementById("service-breakdown");
      if (Object.keys(serviceCounts).length === 0) {{
        el.innerHTML = '<div style="color:#888">No findings for selected file.</div>';
        return;
      }}
      el.innerHTML = Object.entries(serviceCounts).map(([svc, checks]) => {{
        const tags = Object.entries(checks).map(([check, count]) =>
          `<span class="svc-tag">${{check}}: ${{count}}</span>`).join("");
        return `<div class="svc-row"><div class="svc-name">${{svc}}</div>${{tags}}</div>`;
      }}).join("");
    }}
  </script>
</body>
</html>"""

    return html


def save_report(html: str) -> None:
    output_path = "report.html"
    with open(output_path, "w") as f:
        f.write(html)
    print(f"\nReport saved to: {os.path.abspath(output_path)}")
 
 
# Entry point of files
 
def scan_folder(folder, checks, report):
    total_files = 0
    files_with_issues = 0
    scan_results = []

    for filename in sorted(os.listdir(folder)):
        if not (filename.endswith(".yml") or filename.endswith(".yaml")):
            continue

        filepath = os.path.join(folder, filename)
        total_files += 1
        findings = scan_file(filepath, checks)
        scan_results.append({"filename": filename, "findings": findings})

        if findings:
            files_with_issues += 1
            print(f"\nWARNING [{filename}]:")
            print_findings(findings)
        else:
            print(f"OK      [{filename}]: no issues found")

    print(f"\n--- Summary ---")
    print(f"Files scanned      : {total_files}")
    print(f"Files with issues  : {files_with_issues}")

    if report:
        save_report(build_html_report(scan_results, checks, folder))


def scan_single(path, checks, report):
    filename = os.path.basename(path)
    findings = scan_file(path, checks)
    if findings:
        print_findings(findings)
    else:
        print("No misconfigurations found.")
    if report:
        scan_results = [{"filename": filename, "findings": findings}]
        save_report(build_html_report(scan_results, checks, path))

def main():
    parser = argparse.ArgumentParser(description="Static Docker Analyser")
    parser.add_argument("path", help="Path to a docker-compose.yml file or folder")
    parser.add_argument("--report", action="store_true", help="Save results as report.html")
    args = parser.parse_args()
    checks = load_checks()
    if not checks:
        print("[ERROR] No check modules found in checks/ directory.")
        sys.exit(1)
 
    print(f"Loaded {len(checks)} check(s): {', '.join(getattr(c, 'CHECK_NAME', c.__name__) for c in checks)}\n")
    if os.path.isdir(args.path):
        scan_folder(args.path, checks, args.report)
    elif os.path.isfile(args.path):
        scan_single(args.path, checks, args.report)
    else:
        print(f"[ERROR] Path not found: {args.path}")
        sys.exit(1)
 
 
if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()