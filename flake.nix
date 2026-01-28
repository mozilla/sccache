{
  description = "sccache development environment and package";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      version = cargoToml.package.version;

      mkSccache =
        {
          final,
          pname,
          features ? [ ],
          description,
        }:
        final.rustPlatform.buildRustPackage {
          pname = pname;
          inherit version;

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = [ final.pkg-config ];
          buildInputs = [ final.openssl ];

          cargoBuildFlags =
            if features != [ ] then
              [
                "--features"
                (builtins.concatStringsSep "," features)
              ]
            else
              [ ];

          doCheck = false;

          meta = with final.lib; {
            description = description;
            homepage = "https://github.com/mozilla/sccache";
            changelog = "https://github.com/mozilla/sccache/releases/tag/v${version}";
            license = licenses.asl20;
            mainProgram = "sccache";
          };
        };
    in
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
        "i686-linux"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default ];
          };
        in
        {
          packages = {
            default = pkgs.sccache;
            sccache = pkgs.sccache;
            sccache-dist = pkgs.sccache-dist;
          };

          devShells.default = pkgs.mkShell {
            name = "sccache-dev";

            buildInputs = with pkgs; [
              rustup
              openssl
              pkg-config
              gcc
            ];
          };

          formatter = pkgs.alejandra;
        }
      )
    // {
      overlays.default = final: prev: {
        sccache = mkSccache {
          inherit final;
          pname = "sccache";
          description = "Ccache with Cloud Storage";
        };
        sccache-dist = mkSccache {
          inherit final;
          pname = "sccache-dist";
          features = [
            "dist-client"
            "dist-server"
          ];
          description = "Ccache with Cloud Storage and Distributed Compilation";
        };
      };
    };
}
