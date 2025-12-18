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

    # NixOS module
    nixosModule = {
      config,
      lib,
      pkgs,
      ...
    }: {
      options.programs.sccache.enable = lib.mkEnableOption "sccache compilation cache";

      config = lib.mkIf config.programs.sccache.enable {
        environment.systemPackages = [self.packages.${pkgs.system}.sccache];
      };
    };

    # Home-manager module
    homeManagerModule = {
      config,
      lib,
      pkgs,
      ...
    }: {
      options.programs.sccache.enable = lib.mkEnableOption "sccache compilation cache";

      config = lib.mkIf config.programs.sccache.enable {
        home.packages = [self.packages.${pkgs.system}.sccache];
      };
    };
  in
    # Per-system outputs
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
        };
      in {
        packages = {
          default = self.packages.${system}.sccache;

          sccache = pkgs.rustPlatform.buildRustPackage {
            pname = "sccache";
            inherit version;

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = [
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.openssl
            ];

            # Tests cannot run in a pure environment
            # See, https://github.com/mozilla/sccache/issues/460
            doCheck = false;

            meta = with pkgs.lib; {
              description = "Ccache with Cloud Storage";
              homepage = "https://github.com/mozilla/sccache";
              changelog = "https://github.com/mozilla/sccache/releases/tag/v${version}";
              license = licenses.asl20;
              mainProgram = "sccache";
            };
          };
        };

        devShells.default = pkgs.mkShell {
          name = "sccache-dev";

          buildInputs = with pkgs;
            [
              # Rust toolchain management
              rustup

              # OpenSSL for TLS/crypto
              openssl
              pkg-config

              # Build essentials
              gcc
            ];
        };

        formatter = pkgs.alejandra;
      }
    )
    // {
      nixosModules.default = nixosModule;
      nixosModules.sccache = nixosModule;

      homeManagerModules.default = homeManagerModule;
      homeManagerModules.sccache = homeManagerModule;
    };
}
