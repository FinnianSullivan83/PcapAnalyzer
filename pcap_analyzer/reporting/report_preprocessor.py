def preprocess_report_data(report_data):
    unique_files = []
    seen_hashes = set()
    for file_info in report_data.get("extracted_files", []):
        file_hash = file_info.get("hash")
        if file_hash and file_hash not in seen_hashes:
            unique_files.append(file_info)
            seen_hashes.add(file_hash)
    report_data["extracted_files"] = unique_files

    if "suspicious_ips" in report_data:
        report_data["suspicious_ips"] = sorted(report_data["suspicious_ips"],
                                               key=lambda x: x.get("packets", 0),
                                               reverse=True)
    return report_data
