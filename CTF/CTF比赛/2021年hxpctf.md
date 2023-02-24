#  2021年hxpctf复现

## includer's revenge

代码展示

```php
<?php
($_GET['action'] ?? 'read' ) === 'read' ? readfile($_GET['file'] ?? 'index.php') : include_once($_GET['file'] ?? 'index.php');

```



