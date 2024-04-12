# pylint: disable=missing-docstring, expression-not-assigned
import modules.nist.nist

from modules.config import Config

def main():
    config = Config() # pylint: disable=unused-variable

    modules.nist.nist.main() # TODO: This should be put into a new thread pylint: disable=fixme

if __name__ == "__main__":
    main()
