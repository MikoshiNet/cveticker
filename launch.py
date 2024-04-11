# pylint: disable=missing-docstring, expression-not-assigned
import modules.nist.nist

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

def main():
    config = Config() # pylint: disable=unused-variable

    modules.nist.nist.main() # TODO: This should be put into a new thread pylint: disable=fixme

if __name__ == "__main__":
    main()
