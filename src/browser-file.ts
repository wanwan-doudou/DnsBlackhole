const UTF8 = new TextDecoder("utf-8", { fatal: true });

export function downloadBrowserFile(
  filename: string,
  content: BlobPart,
  contentType: string,
): void {
  const url = URL.createObjectURL(new Blob([content], { type: contentType }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function chooseBrowserTextFile(accept: string, maxBytes: number): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = accept;
    input.hidden = true;
    document.body.appendChild(input);

    let settled = false;
    const finish = (value: string | null, error?: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      input.remove();
      if (error !== undefined) {
        reject(error);
      } else {
        resolve(value);
      }
    };

    input.addEventListener("cancel", () => finish(null), { once: true });
    input.addEventListener(
      "change",
      async () => {
        const file = input.files?.[0];
        if (!file) {
          finish(null);
          return;
        }
        if (file.size > maxBytes) {
          finish(null, new Error(`文件超过 ${Math.floor(maxBytes / 1024 / 1024)} MiB，已拒绝读取`));
          return;
        }
        try {
          finish(UTF8.decode(await file.arrayBuffer()));
        } catch (error) {
          finish(null, new Error(`文件必须是有效的 UTF-8 文本：${String(error)}`));
        }
      },
      { once: true },
    );
    input.click();
  });
}
