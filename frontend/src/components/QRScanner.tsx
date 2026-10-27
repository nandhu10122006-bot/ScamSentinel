import React, { useState, useRef, useEffect, useCallback } from 'react';
import jsQR from 'jsqr';
import { QrCode, Upload, Camera, CameraOff, AlertTriangle, CheckCircle2, ArrowRight, RefreshCw } from 'lucide-react';

interface QRScannerProps {
  onScan: (decodedContent: string) => Promise<void>;
  isLoading: boolean;
}

export const QRScanner: React.FC<QRScannerProps> = ({ onScan, isLoading }) => {
  const [activeMode, setActiveMode] = useState<'upload' | 'camera'>('upload');
  const [decodedContent, setDecodedContent] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isProcessingFile, setIsProcessingFile] = useState(false);
  const [isCameraActive, setIsCameraActive] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const animationFrameIdRef = useRef<number | null>(null);

  // Stop camera stream cleanly
  const stopCamera = useCallback(() => {
    if (animationFrameIdRef.current) {
      cancelAnimationFrame(animationFrameIdRef.current);
      animationFrameIdRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setIsCameraActive(false);
  }, []);

  // Clean up camera on unmount or mode switch
  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, [stopCamera]);

  useEffect(() => {
    if (activeMode !== 'camera' && isCameraActive) {
      stopCamera();
    }
  }, [activeMode, isCameraActive, stopCamera]);

  // Decode QR from ImageData
  const decodeFromCanvas = (canvas: HTMLCanvasElement): string | null => {
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth',
    });
    return code ? code.data : null;
  };

  // Handle uploaded QR image file
  const handleFileUpload = (file: File) => {
    setErrorMessage(null);
    setDecodedContent(null);
    setIsProcessingFile(true);

    if (!file.type.startsWith('image/')) {
      setErrorMessage('Please upload a valid image file (PNG, JPG, WebP).');
      setIsProcessingFile(false);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          setErrorMessage('Unable to initialize image processor.');
          setIsProcessingFile(false);
          return;
        }

        ctx.drawImage(img, 0, 0);
        const qrResult = decodeFromCanvas(canvas);

        setIsProcessingFile(false);
        if (qrResult) {
          setDecodedContent(qrResult);
          onScan(qrResult);
        } else {
          setErrorMessage('No valid QR code detected in the uploaded image. Please try a clearer picture.');
        }
      };

      img.onerror = () => {
        setIsProcessingFile(false);
        setErrorMessage('Failed to read image file.');
      };

      img.src = e.target?.result as string;
    };

    reader.onerror = () => {
      setIsProcessingFile(false);
      setErrorMessage('Failed to read file.');
    };

    reader.readAsDataURL(file);
  };

  // Handle live camera stream loop
  const scanCameraFrame = useCallback(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) {
      animationFrameIdRef.current = requestAnimationFrame(scanCameraFrame);
      return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const qrResult = decodeFromCanvas(canvas);

      if (qrResult) {
        setDecodedContent(qrResult);
        stopCamera();
        onScan(qrResult);
        return;
      }
    }

    animationFrameIdRef.current = requestAnimationFrame(scanCameraFrame);
  }, [onScan, stopCamera]);

  const startCamera = async () => {
    setErrorMessage(null);
    setDecodedContent(null);

    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Webcam access is not supported by your browser.');
      }

      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
      });

      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
        setIsCameraActive(true);
        animationFrameIdRef.current = requestAnimationFrame(scanCameraFrame);
      }
    } catch (err: unknown) {
      const errString = err instanceof Error ? err.message : 'Camera access denied or unavailable.';
      setErrorMessage(`Camera error: ${errString}`);
      setIsCameraActive(false);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="w-full bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <QrCode className="w-5 h-5" />
          </div>
          <h2 className="text-base font-semibold text-white">QR Scanner</h2>
        </div>

        {/* Mode Toggle */}
        <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setActiveMode('upload')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeMode === 'upload'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Image</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveMode('camera')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeMode === 'camera'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Camera className="w-3.5 h-3.5" />
            <span>Webcam Scan</span>
          </button>
        </div>
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        onChange={(e) => {
          if (e.target.files && e.target.files[0]) {
            handleFileUpload(e.target.files[0]);
          }
        }}
        className="hidden"
      />

      {/* Upload View */}
      {activeMode === 'upload' && (
        <div
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
            dragActive
              ? 'border-purple-400 bg-purple-500/10'
              : 'border-slate-700/80 hover:border-slate-600 bg-slate-950/50 hover:bg-slate-950/80'
          }`}
        >
          {isProcessingFile ? (
            <div className="flex flex-col items-center gap-3">
              <RefreshCw className="w-8 h-8 text-purple-400 animate-spin" />
              <p className="text-sm font-medium text-slate-200">Decoding QR Code...</p>
            </div>
          ) : (
            <>
              <div className="w-12 h-12 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center mb-3">
                <Upload className="w-6 h-6" />
              </div>
              <p className="text-sm font-semibold text-slate-200">
                Upload or drop a QR code image
              </p>
            </>
          )}
        </div>
      )}

      {/* Camera View */}
      {activeMode === 'camera' && (
        <div className="relative rounded-xl overflow-hidden bg-black border border-slate-800 flex flex-col items-center justify-center min-h-[260px]">
          <video
            ref={videoRef}
            playsInline
            muted
            className={`w-full max-h-[320px] object-cover ${isCameraActive ? 'block' : 'hidden'}`}
          />
          <canvas ref={canvasRef} className="hidden" />

          {/* Scanner Reticle Overlay */}
          {isCameraActive && (
            <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
              <div className="w-48 h-48 border-2 border-purple-400/80 rounded-2xl relative animate-pulse shadow-[0_0_20px_rgba(168,85,247,0.3)]">
                <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-purple-300" />
                <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-purple-300" />
                <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-purple-300" />
                <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-purple-300" />
              </div>
            </div>
          )}

          {!isCameraActive && (
            <div className="p-6 text-center flex flex-col items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center">
                <Camera className="w-6 h-6" />
              </div>
              <p className="text-sm text-slate-300 font-medium">Camera scanning inactive</p>
              <button
                type="button"
                onClick={startCamera}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold uppercase tracking-wider transition-all shadow-md hover:shadow-purple-500/20"
              >
                <Camera className="w-4 h-4" />
                <span>Start Camera Scanner</span>
              </button>
            </div>
          )}

          {isCameraActive && (
            <div className="absolute bottom-3 left-1/2 -translate-x-1/2 z-10">
              <button
                type="button"
                onClick={stopCamera}
                className="flex items-center gap-2 px-3 py-1.5 bg-rose-600/90 hover:bg-rose-500 text-white rounded-lg text-xs font-medium backdrop-blur-md transition-all shadow-md"
              >
                <CameraOff className="w-4 h-4" />
                <span>Stop Camera</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Error State */}
      {errorMessage && (
        <div className="mt-4 flex items-center gap-2 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 px-3 py-2 rounded-lg">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Decoded Content Banner */}
      {decodedContent && (
        <div className="mt-4 p-3.5 rounded-xl bg-slate-950 border border-purple-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 overflow-hidden">
            <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-purple-400 font-semibold">Decoded QR Destination</p>
              <p className="text-xs text-slate-200 font-mono break-all truncate">{decodedContent}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onScan(decodedContent)}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold uppercase tracking-wider transition-all self-end sm:self-auto flex-shrink-0 disabled:opacity-50"
          >
            <span>Analyze</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
};

