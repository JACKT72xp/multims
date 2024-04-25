class Multims < Formula
    desc "Multims is a CLI tool for managing Kubernetes"
    homepage "https://github.com/jackt72xp/multims"
    url "https://github.com/jackt72xp/multims/archive/v1.0.0.tar.gz"
    sha256 "aqui_va_el_sha256_del_archivo_tar_gz"
  
    def install
      system "go", "build", "-o", "multims"
      bin.install "multims"
    end
  
    test do
      system "#{bin}/multims", "--version"
    end
  end
  