from flask import Flask, render_template, jsonify, request, send_from_directory, abort
import os
import json

app = Flask(__name__)

LOG_PATH = "/var/logs/"
FTP_FILES = "/var/files_ftp/"
TIMESTAMP_CHECK = "2025-01-01T00:00:00.000000"
TIMESTAMP_MAX_CHECK = "9999-12-31t23:59:59.999999"


@app.route("/")
def index():
    return render_template("logs.html")


def read_logs(path):
    logs = []
    for obj in os.scandir(path):
        if obj.is_file():
            with open(obj.path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log_dict = json.loads(line)
                        logs.append(log_dict)
                    except json.JSONDecodeError:
                        continue
        elif obj.is_dir():
            logs.extend(read_logs(obj.path))
    return logs


def parse_search(search_text):
    if not search_text:
        return []

    and_groups = [group.strip() for group in search_text.split("&&")]
    parsed = []

    for group in and_groups:
        or_terms_raw = [term.strip() for term in group.split("||")]
        or_terms = []
        for term in or_terms_raw:
            if ":" in term:
                key, value = term.split(":", 1)
                strict = False
                value = value.strip()
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1].strip()
                    strict = True
                or_terms.append((key.strip(), value, strict))
            else:
                or_terms.append((None, term.strip(), False))  # free-text in data
        parsed.append(or_terms)
    return parsed


def log_matches(log, parsed_search):
    if not parsed_search:
        return True

    for and_group in parsed_search:
        or_group_match = False
        for key, value, strict in and_group:
            if key:
                if strict:
                    if value.lower() == str(log.get(key, "")).lower():
                        or_group_match = True
                        break
                else:
                    if value.lower() in str(log.get(key, "")).lower():
                        or_group_match = True
                        break
            else:
                if value.lower() in log.get("data", "").lower():
                    or_group_match = True
                    break
        if not or_group_match:
            return False
    return True


@app.route("/api/logs", methods=["POST"])
def logs():
    search = request.get_json(silent=True) or {}
    try:
        timestamp = str(
            search.get("timestamp", TIMESTAMP_MAX_CHECK) or TIMESTAMP_MAX_CHECK
        )
    except (ValueError, TypeError):
        timestamp = TIMESTAMP_CHECK

    if timestamp < TIMESTAMP_CHECK:
        timestamp = TIMESTAMP_MAX_CHECK
    try:
        limit = abs(int(search.get("limit", "50") or "50"))
    except (ValueError, TypeError):
        limit = 50
    print(limit)
    port = search.get("port", "")
    path = os.path.join(LOG_PATH, str(port)) if port else LOG_PATH

    logs_list = read_logs(path)
    logs_list.sort(key=lambda x: x["time"], reverse=True)
    logs_list = [log for log in logs_list if log["time"] < timestamp]

    search_text = search.get("search", "")
    parsed_search = parse_search(search_text)
    logs_list = [log for log in logs_list if log_matches(log, parsed_search)][:limit]
    return jsonify(logs_list)


@app.route("/files", defaults={"req_path": ""})
@app.route("/files/<path:req_path>")
def serve_file(req_path):
    abs_path = os.path.join(FTP_FILES, req_path)

    if not os.path.exists(abs_path):
        return abort(404)

    if os.path.isfile(abs_path):
        return send_from_directory(
            os.path.dirname(abs_path), os.path.basename(abs_path)
        )

    files = os.listdir(abs_path)
    files.sort()
    return render_template(
        "files_ftp.html", files=files, req_path=req_path, base_dir=FTP_FILES, os=os
    )


if __name__ == "__main__":
    app.run("0.0.0.0", port=80)
