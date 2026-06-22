import React, { useRef, useState, useEffect } from "react";
import { UploadCloud, X, FileText } from "lucide-react";

/**
 * FileThumbnail — safely creates and revokes an object URL for a File.
 */
function FileThumbnail({ file }) {
  const [url, setUrl] = useState(null);
  const isImage = file?.type?.startsWith("image/");

  useEffect(() => {
    if (!file || !isImage) return;
    const objectUrl = URL.createObjectURL(file);
    setUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file, isImage]);

  if (!file) return null;

  if (isImage && url) {
    return <img src={url} alt={file.name} className="w-full h-full object-cover" />;
  }
  return (
    <div className="w-full h-full flex flex-col items-center justify-center gap-1 bg-gray-100 p-2">
      <FileText className="w-7 h-7 text-red-400" />
      <p className="text-[9px] text-gray-500 truncate w-full text-center px-1">{file.name}</p>
    </div>
  );
}

/**
 * FileDropzone — drag-and-drop or click-to-select file upload with preview grid.
 *
 * Props:
 *   field       {string}                    — logical field name (for data-field targeting)
 *   label       {string}                    — display label
 *   accept      {string}                    — MIME type string (e.g. "image/*" or ".pdf")
 *   multiple    {boolean}                   — allow multiple files (default: false)
 *   maxSizeMB   {number}                    — per-file size cap in MB (default: 10)
 *   files       {File[]}                    — current selected files (controlled)
 *   onChange    {(files: File[]) => void}   — called with the updated file list
 *   error       {string|undefined}          — validation error message
 *   required    {boolean}
 */
export default function FileDropzone({
  field,
  label,
  accept = "image/*",
  multiple = false,
  maxSizeMB = 10,
  files = [],
  onChange,
  error,
  required,
}) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  const maxBytes = maxSizeMB * 1024 * 1024;

  const processFiles = (incoming) => {
    const valid = [];
    for (const f of incoming) {
      if (f.size > maxBytes) {
        // toast is not imported here to keep the kit dependency-free; caller handles UX
        console.warn(`[FileDropzone] "${f.name}" exceeds ${maxSizeMB} MB — skipped`);
        continue;
      }
      valid.push(f);
    }
    if (valid.length === 0) return;
    onChange(multiple ? [...files, ...valid] : [valid[0]]);
  };

  const handleInputChange = (e) => {
    processFiles(Array.from(e.target.files || []));
    e.target.value = ""; // reset so same file can be re-added after removal
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    processFiles(Array.from(e.dataTransfer.files || []));
  };

  const removeFile = (index) => {
    onChange(files.filter((_, i) => i !== index));
  };

  return (
    <div data-field={field} className={`border rounded-xl p-4 transition-colors ${error ? "border-red-400 bg-red-50/20" : "border-gray-200 bg-gray-50/50"}`}>
      {/* Label */}
      <p className="block text-sm font-medium text-gray-700 mb-3">
        {label}
        {required && <span className="text-red-500 ml-0.5">*</span>}
      </p>

      {/* Drop zone */}
      <div
        className={[
          "relative flex flex-col items-center justify-center gap-2 border-2 border-dashed rounded-xl py-6 px-4 cursor-pointer transition-all",
          dragging ? "border-blue-500 bg-blue-50" : "border-gray-200 hover:border-blue-300 hover:bg-blue-50/30",
        ].join(" ")}
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        role="button"
        tabIndex={0}
        onKeyDown={e => e.key === "Enter" && inputRef.current?.click()}
        aria-label={`Upload ${label}`}
      >
        <UploadCloud className={`w-8 h-8 ${dragging ? "text-blue-500" : "text-gray-300"}`} />
        <p className="text-xs text-gray-500 text-center">
          <span className="font-semibold text-blue-600">Click to upload</span> or drag and drop
        </p>
        <p className="text-[10px] text-gray-400">
          {accept} · Max {maxSizeMB} MB {multiple ? "· Multiple allowed" : "· Single file"}
        </p>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          multiple={multiple}
          className="hidden"
          onChange={handleInputChange}
          aria-hidden="true"
        />
      </div>

      {/* Error */}
      {error && (
        <p role="alert" className="text-xs text-red-500 mt-2 flex items-center gap-1">
          <span>⚠</span> {error}
        </p>
      )}

      {/* Preview grid */}
      {files.length > 0 && (
        <div className="mt-3">
          <p className="text-xs text-gray-500 mb-2">
            {files.length} file{files.length > 1 ? "s" : ""} selected
          </p>
          <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-2">
            {files.map((file, i) => (
              <div
                key={`${field}-${i}-${file.name}`}
                className="group relative rounded-lg overflow-hidden border border-gray-200 bg-white shadow-sm aspect-square"
              >
                <FileThumbnail file={file} />
                {/* Remove button */}
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); removeFile(i); }}
                  className="absolute top-1 right-1 w-5 h-5 rounded-full bg-red-500 text-white text-xs flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity hover:bg-red-600 shadow"
                  aria-label={`Remove ${file.name}`}
                >
                  <X className="w-3 h-3" />
                </button>
                {/* File name */}
                <div className="absolute bottom-0 left-0 right-0 bg-black/40 px-1 py-0.5">
                  <p className="text-[9px] text-white truncate">{file.name}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
