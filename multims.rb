class Multims < Formula
    desc "Multims is a CLI tool for managing Kubernetes"
    homepage "https://github.com/jackt72xp/multims"
    
    if Hardware::CPU.intel?
      url "https://github.com/JACKT72xp/multims/releases/download/v1.0.2/multims-darwin-amd64.tar.gz"
      sha256 "9c79a22d25bf1ac740b91855816be512eb5ea7c02295817418b7189aaf0fe7eb"
    elsif Hardware::CPU.arm?
      url "https://github.com/JACKT72xp/multims/releases/download/v1.02/multims-darwin-arm64.tar.gz"
      sha256 "fd8b36080c39294b6c4becdd36cf770fd956c376c0b01f0da4b256910eb4b4be"
    end
    
    depends_on "fswatch"
    
    def install
      # Instala el binario 'multims' en /usr/bin
      bin.install "multims-darwin-#{Hardware::CPU.arch}" => "multims"
      # Instala el directorio 'templates' dentro del directorio de la fórmula
      (share/"multims/templates").install "templates"
    end
    
    test do
      system "#{bin}/multims", "--version"
    end
  end
  