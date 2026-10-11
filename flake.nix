{
  description = "Multi-architecture assembler library built on LLVM's MC layer";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:
    let
      inherit (inputs) nixpkgs fenix;
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs (lib.systems.doubles.linux ++ lib.systems.doubles.darwin);
      pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          keystone = pkgs.callPackage ./nix/package.nix { };
          keystone-rust = pkgs.callPackage ./nix/rust.nix { inherit (self.packages.${system}) keystone; };
          default = self.packages.${system}.keystone;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          # .rustfmt.toml uses unstable options, so only rustfmt comes from nightly.
          default = pkgs.callPackage ./nix/shell.nix {
            rustfmt = fenix.packages.${system}.latest.rustfmt or pkgs.rustfmt;
          };
        }
      );

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) keystone keystone-rust;
      });

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
