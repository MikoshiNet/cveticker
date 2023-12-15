import hashlib

# pylint: disable=missing-docstring

class Data:
    def __init__(self, post:str, content:str, mentioned_cves:list, cve:str=None):
        self.post = hashlib.sha256(post.encode('utf-8')).hexdigest()
        self.content = content
        self.mentioned_cves = mentioned_cves
        self.cve = cve # Unique CVE

    def __str__(self):
        return self.mentioned_cves


class Dataset:
    def __init__(self, dataset:set[Data]=None) -> None:
        self.dataset: set[Data] = dataset if dataset else set()

    def __eq__(self, other):
        if isinstance(other, Dataset):
            # Assuming you want to compare a specific attribute like 'post' in each Data object
            return all(any(d.post == o.post for o in other.dataset) for d in self.dataset)
        return False

    def __len__(self) -> int:
        return len(self.dataset)

    def __iter__(self):
        return iter(self.dataset)

    def __contains__(self, item) -> bool:
        if isinstance(item, Data):
            return item in self.dataset
        elif isinstance(item,str):
            return item in [hashlib.sha256(data.post.encode()) for data in self.dataset]

    def add(self, data:Data) -> None:
        self.dataset.add(data)

class DatasetBuilder:
    def __init__(self):
        return self