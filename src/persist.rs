use async_std::fs;
use async_std::io::ErrorKind;
use async_std::path::Path;

pub(crate) async fn read_if_exist(
    dir: impl AsRef<Path>,
    file: impl AsRef<Path>,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let path = dir.as_ref().join(file);
    match fs::read(path).await {
        Ok(content) => Ok(Some(content)),
        Err(err) => match err.kind() {
            ErrorKind::NotFound => Ok(None),
            _ => Err(err.into()),
        },
    }
}

pub(crate) async fn write(
    dir: impl AsRef<Path>,
    file: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<(), std::io::Error> {
    let path = dir.as_ref().join(file);
    Ok(fs::write(path, contents).await?)
}
