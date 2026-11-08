{
  description = "straps-classifier — tool calls rated before confirmation; scoped denials enforced by the guard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    straps.url = "git+https://github.com/ducharmemp/straps";
    straps.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, straps }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkClassifier = pkgs: pkgs.vimUtils.buildVimPlugin {
        pname = "straps-classifier";
        version = self.shortRev or self.dirtyShortRev or "dev";
        src = self;
        # curl is the only runtime dependency (fn.typesafe shells out to it).
        # Not wrapped in: surface it through the nixvim module's extraPackages,
        # which straps already does for its own provider.
        meta = {
          description = "Risk classifier for straps.nvim tool calls, backed by TypeSafe's System One API";
          license = nixpkgs.lib.licenses.mit;
        };
      };
    in
    {
      packages = forAllSystems (pkgs: rec {
        straps-classifier = mkClassifier pkgs;
        default = straps-classifier;
      });

      overlays.default = final: prev: {
        vimPlugins = prev.vimPlugins // { straps-classifier = mkClassifier final; };
      };

      # Import into a nixvim configuration ALONGSIDE the straps module:
      #   imports = [
      #     straps.nixvimModules.default
      #     straps-classifier.nixvimModules.default
      #   ];
      #   plugins.straps.enable = true;
      #   plugins.straps-classifier.enable = true;
      #
      # The classifier's setup() must run while the guard chain is still
      # unfrozen — straps freezes it when the first session opens — and after
      # straps' own setup() has registered hook.confirm, which this plugin
      # chains. Both are satisfied by emitting our extraConfigLua with
      # lib.mkAfter: nixvim concatenates the blocks, straps' setup lands first,
      # and no session can exist at startup.
      nixvimModules = rec {
        straps-classifier = { lib, config, pkgs, ... }:
          let
            cfg = config.plugins.straps-classifier;
          in
          {
            options.plugins.straps-classifier = {
              enable = lib.mkEnableOption "straps-classifier, the tool-call risk classifier";
              package = lib.mkOption {
                type = lib.types.package;
                default = mkClassifier pkgs;
                defaultText = lib.literalExpression ''straps-classifier.packages.''${system}.default'';
                description = "The straps-classifier plugin package.";
              };
              settings = lib.mkOption {
                type = with lib.types; attrsOf anything;
                default = { };
                example = {
                  deny_threshold = 0.9;
                  always_deny_patterns = [ "rm%s+%-rf%s+/" "%.ssh/id_" ];
                };
                description = ''
                  Passed verbatim to require("straps_classifier").setup(). See
                  the config table in lua/straps_classifier/init.lua for every
                  key.

                  Note that with this plugin enabled and no TypeSafe API key
                  reachable, EVERY tool call is denied. That is deliberate: an
                  unconfigured classifier knows nothing about the call in front
                  of it, and knowing nothing is suspicion, not permission.
                '';
              };
            };
            config = lib.mkIf cfg.enable {
              extraPlugins = [ cfg.package ];
              extraPackages = [ pkgs.curl ];
              extraConfigLua = lib.mkAfter ''
                require("straps_classifier").setup(${lib.generators.toLua { } cfg.settings})
              '';
            };
          };
        default = straps-classifier;
      };

      checks = forAllSystems (pkgs: {
        tests = pkgs.stdenvNoCC.mkDerivation {
          name = "straps-classifier-tests";
          src = self;
          nativeBuildInputs = [
            pkgs.neovim pkgs.curl
            pkgs.luajitPackages.busted pkgs.luajitPackages.nlua
          ];
          dontBuild = true;
          doCheck = true;
          checkPhase = ''
            export HOME=$TMPDIR
            export XDG_DATA_HOME=$TMPDIR/data XDG_STATE_HOME=$TMPDIR/state XDG_CACHE_HOME=$TMPDIR/cache
            # The integration tests need a straps checkout on the rtp; take it
            # from the flake input rather than the ../straps default.
            export STRAPS_ROOT=${straps}
            # live_spec.lua is the only networked test and is pending without a
            # key, which is what it should do in a sandboxed build. One busted
            # process per spec: the specs share the registry singleton.
            fail=0
            for t in tests/*_spec.lua; do
              echo "== $t"
              busted "$t" || fail=1
            done
            [ "$fail" = 0 ]
          '';
          installPhase = "touch $out";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.neovim pkgs.curl
            pkgs.luajitPackages.busted pkgs.luajitPackages.nlua
          ];
          shellHook = ''
            export STRAPS_ROOT=''${STRAPS_ROOT:-${straps}}
          '';
        };
      });
    };
}
