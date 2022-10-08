コマンドラインオプション:
telnetls (接続先サーバー, 必須) (ポート, なければ443になる)
実行例:
telnetls ja.wikipedia.org
telnetls google.com 443

telnetlsが読むファイル一覧:
telnetls.txt : このファイルの内容を相手サーバーへの接続直後に送信します
certs/*.pem : CA証明書を置くことでオレオレ証明書を使えるようになります