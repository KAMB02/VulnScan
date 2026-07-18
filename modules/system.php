<?php
if (file_exists("/data/data/com.termux/files/usr/bin")) {
  $system = "termux";
} elseif (is_dir("/usr/bin")) {
  $system = "linux";
} else {
  $system = "unknown";
}
