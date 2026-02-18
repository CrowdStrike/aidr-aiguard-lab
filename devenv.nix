{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  dotenv.enable = true;

  languages.python = {
    enable = true;
    version = "3.12";
    uv = {
      enable = true;
      sync = {
        enable = true;
        allExtras = true;
        allGroups = true;
      };
    };
  };

  git-hooks.hooks = {
    alejandra.enable = true;
    ruff.enable = true;
    ruff-format.enable = true;
  };
}
