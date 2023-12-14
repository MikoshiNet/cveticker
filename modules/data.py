import hashlib

# pylint: disable=missing-docstring

class Data:
    def __init__(self, post, content, mentioned_cves, cve=None):
        self.post = hashlib.sha256(post.encode('utf-8')).hexdigest()
        self.content = content
        self.mentioned_cves = mentioned_cves
        self.cve = cve # Unique CVE


class Dataset:
    def __init__(self) -> None:
        self.dataset: set[Data] = set()

    def __eq__(self, other):
        return self.dataset == other.dataset # Maybe change to only check dataset[for].post

    def __len__(self) -> int:
        return len(self.dataset)

    def __iter__(self):
        return iter(self.dataset)
    
    # def __next__(self):
    #     if self.dataset.current > self.dataset.high:
    #         raise StopIteration
        
    def __getitem__(self, key):
        self.dataset[key]

    def __setitem__(self, key, value):
        self.dataset[key] = value

    def __delitem__(self, key, value):
        self.dataset[key] = value

    def __contains__(self, item) -> bool:
        if isinstance(item, Data):
            return item in self.dataset
        elif isinstance(item,str):
            return item in [hashlib.sha256(data.post.encoding()) for data in self.dataset]

    def add(self, data:Data) -> None:
        self.dataset.add(data)
