class Multims < Formula
  desc "Multims is a tool for managing and syncing Kubernetes configurations"
  homepage "https://github.com/JACKT72xp/multims"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/JACKT72xp/multims/releases/download/v1.0.0/multims_arm64"
      sha256 "..."  # Reemplaza con el valor SHA256 del binario ARM

      def install
        bin.install "multims_arm64" => "multims"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/JACKT72xp/multims/releases/download/v1.0.0/multims_amd64"
      sha256 "..."  # Reemplaza con el valor SHA256 del binario AMD64

      def install
        bin.install "multims_amd64" => "multims"
      end
    end
  end

  test do
    system "#{bin}/multims", "--version"
  end
end