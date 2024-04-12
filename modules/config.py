from modules.file_handler import get_file_json_content

class Config:
    def __init__(self) -> None:
        try:
            config = get_file_json_content("config.json")
            self.rss_urls = config["rss"]["targets"]
            self.nist_api_key = config["nist"]["api_key"]
            self.nist_filter_cvss_score = config["nist"]["filters"]["cvss_score"]
        except FileNotFoundError:
            print("config.json missing")
