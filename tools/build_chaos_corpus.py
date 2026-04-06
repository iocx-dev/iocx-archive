import os
import io
import zipfile
import tarfile
import tempfile
import py7zr


BASE = "chaos_corpus"


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def make_zip_tiny():
    path = os.path.join(BASE, "zip", "tiny.zip")
    ensure_dir(os.path.dirname(path))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", b"A")


def make_zip_truncated():
    src = os.path.join(BASE, "zip", "tiny.zip")
    dst = os.path.join(BASE, "zip", "truncated.zip")
    ensure_dir(os.path.dirname(dst))
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(data[: len(data) // 2]) # chop in half


def make_zip_path_traversal():
    path = os.path.join(BASE, "zip", "path_traversal.zip")
    ensure_dir(os.path.dirname(path))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("../evil.txt", b"X")
        z.writestr("nested/../../escape.txt", b"Y")


def make_zip_unicode():
    path = os.path.join(BASE, "zip", "unicode_names.zip")
    ensure_dir(os.path.dirname(path))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("üñïçødé.txt", b"U")
        z.writestr("子/文件.txt", b"C")


def make_zip_nested_depth(n=10):
    ensure_dir(os.path.join(BASE, "zip"))
    prev = None
    for i in range(n):
        name = os.path.join(BASE, "zip", f"nested_{i}.zip")
        with zipfile.ZipFile(name, "w") as z:
            if prev:
                z.write(prev, os.path.basename(prev))
            else:
                z.writestr("leaf.txt", b"L")
        prev = name
    # outermost
    os.rename(prev, os.path.join(BASE, "zip", "nested_depth_10.zip"))


def make_tar_tiny():
    path = os.path.join(BASE, "tar", "tiny.tar")
    ensure_dir(os.path.dirname(path))
    with tarfile.open(path, "w") as t:
        info = tarfile.TarInfo("a.txt")
        data = b"A"
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))


def make_tar_truncated():
    src = os.path.join(BASE, "tar", "tiny.tar")
    dst = os.path.join(BASE, "tar", "truncated.tar")
    ensure_dir(os.path.dirname(dst))
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(data[: len(data) // 2])


def make_tar_path_traversal():
    path = os.path.join(BASE, "tar", "path_traversal.tar")
    ensure_dir(os.path.dirname(path))
    with tarfile.open(path, "w") as t:
        info = tarfile.TarInfo("../evil.txt")
        data = b"X"
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))


def make_7z_tiny():
    path = os.path.join(BASE, "7z", "tiny.7z")
    ensure_dir(os.path.dirname(path))
    with tempfile.TemporaryDirectory() as tmp:
        fpath = os.path.join(tmp, "a.txt")
        with open(fpath, "wb") as f:
            f.write(b"A")
        with py7zr.SevenZipFile(path, "w") as z:
            z.writeall(tmp, arcname="")


def make_7z_truncated():
    src = os.path.join(BASE, "7z", "tiny.7z")
    dst = os.path.join(BASE, "7z", "truncated.7z")
    ensure_dir(os.path.dirname(dst))
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(data[: len(data) // 2])


def build_all():
    make_zip_tiny()
    make_zip_truncated()
    make_zip_path_traversal()
    make_zip_unicode()
    make_zip_nested_depth()

    make_tar_tiny()
    make_tar_truncated()
    make_tar_path_traversal()

    make_7z_tiny()
    make_7z_truncated()


if __name__ == "__main__":
    build_all()
