class Multims < Formula
  desc "Multims is a tool for managing and syncing Kubernetes configurations"
  homepage "https://github.com/jacktorpoco/multims"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jacktorpoco/multims/releases/download/v1.0.0/multims_arm64"
      sha256 "..."  # SHA256 del binario para arm64

      def install
        bin.install "multims_arm64" => "multims"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/jacktorpoco/multims/releases/download/v1.0.0/multims_amd64"
      sha256 "..."  # SHA256 del binario para amd64

      def install
        bin.install "multims_amd64" => "multims"
      end
    end
  end

  test do
    system "#{bin}/multims", "--version"
  end
end