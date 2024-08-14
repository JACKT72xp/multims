class Multims < Formula
    desc "Multims is a CLI tool for managing Kubernetes"
    homepage "https://github.com/jackt72xp/multims"
  
    if Hardware::CPU.intel?
      url "https://github.com/JACKT72xp/multims/releases/download/v1.0.0/multims-darwin-amd64.tar.gz"
      sha256 "3ae0cbf75e137b3dd81c788c94d15e0e8ab3d35f8306e99aa787f9c49a2bd811"
    elsif Hardware::CPU.arm?
      url "https://github.com/JACKT72xp/multims/releases/download/v1.0.0/multims-darwin-arm64.tar.gz"
      sha256 "b9d02162b426bfe53ae4734a1b01effbd4ad74dbb0aba76f378de46c157107e1"
    end
  
    depends_on "fswatch"
  
    def install
      # Instala el ejecutable 'multims' y el directorio 'scripts'
      bin.install "multims"
      prefix.install "scripts"
    end
  
    test do
      system "#{bin}/multims", "--version"
    end
  end
  