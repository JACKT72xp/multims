class Multims < Formula
    desc "MultiMS is a tool to manage multiple Minecraft servers on a single machine."
    homepage "https://github.com/JACKT72xp/multims"
    url "https://github.com/JACKT72xp/multims/archive/refs/tags/v1.0.11.tar.gz"
    sha256 "c3b808ba36c8c4da58cd80a270722ebd2b688690031501d2b159c0b1457d7b02"
    version "1.0.11"
  
    def install
        # Change into the directory containing the project
        cd "multims-1.0.11" do  # Adjust based on actual directory name
          system "make"  # Run make with no specific target
        end
      
        # Install the binary
        arch = Hardware::CPU.arm? ? "arm64" : "amd64"
        bin.install "dist/multims_darwin_#{arch}/multims" => "multims"
      end
      
      
  
    test do
      system "#{bin}/multims", "--version"
    end
  end
  