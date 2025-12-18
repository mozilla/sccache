{
  description = "sccache development environment and package";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: let
    cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    version = cargoToml.package.version;

    mkSccache = final:
      final.rustPlatform.buildRustPackage {
        pname = "sccache";
        inherit version;

        src = ./.;

        cargoLock = {
          lockFile = ./Cargo.lock;
        };

        nativeBuildInputs = [final.pkg-config];
        buildInputs = [final.openssl];

        doCheck = false;

        meta = with final.lib; {
          description = "Ccache with Cloud Storage";
          homepage = "https://github.com/mozilla/sccache";
          changelog = "https://github.com/mozilla/sccache/releases/tag/v${version}";
          license = licenses.asl20;
          mainProgram = "sccache";
        };
      };
  in
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
      "i686-linux"
    ] (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [self.overlays.default];
        };
      in {
        packages = {
          default = pkgs.sccache;
          sccache = pkgs.sccache;
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
        sccache = mkSccache final;
      };
    };
}
