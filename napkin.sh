#!/bin/bash 
# Developed by Paul Haas <Paul.J.Haas@gmail.com>
# Licensed under the GNU Public License version 3.0 
# Process Burp Suite Professional's session files for interesting content

function filter() {
	MAXLENGTH=255
	# Cleanup unnecessary whitespace and limit line length, remove empty lines and sort
	sed -r 's/^\s*//g;s/\s*$//g;s/(\s)+/\1/g' | awk "{if (length<$MAXLENGTH) print }" | grep -v "^ *$" | sort -Vu
}

# Check for xmlstarlet
if ! which 'xmlstarlet' >/dev/null; then 
	echo "# xmlstarlet program is missing, please run apt-get install xmlstarlet"
	exit 1 
fi

FILECOUNT=$(ls -1 *.zip *.session 2>/dev/null | wc -l)
if [ $FILECOUNT != 1 ]
then 
  echo "Process Burp Suite's session files"
  echo "Usage: Place a single Burp Session File with extension .zip or .session in folder and rerun"
  exit 1
fi 

SESSIONFILE=$(ls -1 *.zip *.session | head -n1)
OUTDIR="out"
PARSEDFILE="$OUTDIR/burp.xml"
RUNDIR=$(pwd)
PATH="$PATH:."
NULL="/dev/null"
IFS=$'\n'^\s*//

# Ensure that they provided a session file
if [[ !((  -f "$SESSIONFILE" )) ]]; then
  echo -e "# Could not find Burp Session File: '$SESSIONFILE'"
  exit 2
fi

# Create output directory
mkdir "$OUTDIR" 2> "$NULL"

# Attempt to convert Burp's Session file into a well-formed XML Document
echo "# Converting Burp Session file to XML: '$SESSIONFILE' -> '$PARSEDFILE' - and validating it:"
burp2xml.py "$SESSIONFILE" "$PARSEDFILE"
xmlstarlet val "$PARSEDFILE" 2> /dev/null #| sed 's/^/# /'
if [ "$?" -ne 0 ]; then
	echo "# Unable to validate '$PARSEDFILE' as XML"
	exit 3
fi

# Targets specified in Burp - We should use these rather than require them from the command line
echo "# Targets specified in Burp"
xmlstarlet sel -T -t -m burp/config/target/name -v '.' -n "$PARSEDFILE" > "$OUTDIR/ctn.txt"
xmlstarlet sel -T -t -m burp/config/target/value -v '.' -n "$PARSEDFILE" > "$OUTDIR/ctv.txt"
paste -d'=' "$OUTDIR/ctn.txt" "$OUTDIR/ctv.txt" > "$OUTDIR/burp_config.txt" 
grep "^scopeinclude" "$OUTDIR/burp_config.txt" | cut -d'=' -f2 | sed 's/^[0-9]*\.[0-9]\.[0-9]*\.//' | cut -d'$' -f1 | tr -d '^\\' > "$OUTDIR/targets.txt"
rm "$OUTDIR/ctn.txt" "$OUTDIR/ctv.txt" # "$OUTDIR/burp_config.txt"

# 1st Line Request Information
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v "substring-before(../../info/request,'&#10;')" -n "$PARSEDFILE" | sort -u > "$OUTDIR/request_lines.txt"
cat "$OUTDIR/request_lines.txt" | cut -d' ' -f1 | sort -u > "$OUTDIR/request_verbs.txt" 
cat "$OUTDIR/request_lines.txt" | awk -F' ' '{print $NF}' | sort -u > "$OUTDIR/request_versions.txt" 
rm "$OUTDIR/request_lines.txt"

# 1st Line Response Information
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v "substring-before(../../info/response,'&#10;')" -n "$PARSEDFILE" | sort -u > "$OUTDIR/response_lines.txt"
cat "$OUTDIR/response_lines.txt" | cut -d' ' -f1 | sort -u > "$OUTDIR/response_versions.txt"
cat "$OUTDIR/response_lines.txt" | cut -d' ' -f2 | sort -u > "$OUTDIR/response_codes.txt"
cat "$OUTDIR/response_lines.txt" | cut -d' ' -f1-2 --complement | sort -u > "$OUTDIR/response_verbs.txt"

# All URLS
echo "# All URLS"
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v 'https' -o '://' -v "host" -v "../file" -o "&#09;" -v "substring-after(../../info/request,'&#10;&#10;')" -n "$PARSEDFILE" | sed 's/^False/http/;s/^True/https/;s/^UKNOWN/http/' | grep -i '^http\(s\)\?://' > "$OUTDIR/urls.txt" 

cat "$OUTDIR/urls.txt" | grep -e $'\t--*' | sed 's/\t-*.*/\t<Content-Type: multipart>/' | sort -u > "$OUTDIR/multipart.txt" # Save <Content-Type: multipart> requests
if [ -s "$OUTDIR/multipart.txt" ];
then
	echo "# Detected <Content-Type: multipart> requests in '$OUTDIR/post_multipart.txt', removing them from '$OUTDIR/urls.txt' for manual analysis"
	sed -i '/\t--*/d' "$OUTDIR/urls.txt" # Remove <Content-Type: multipart> requests from the rest of our urls.txt
fi

# Request Bodies
#xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v "substring-after(../../info/request[not(@dt='dt:binary.base64')],'&#10;&#10;')" -n "$PARSEDFILE" | sort -u > "$OUTDIR/request_body.txt"

# Target URLS
echo "# Target URLS"
grep -f "$OUTDIR/targets.txt" "$OUTDIR/urls.txt" > "$OUTDIR/target_urls.txt"
grep -v -f "$OUTDIR/targets.txt" "$OUTDIR/urls.txt" > "$OUTDIR/offsite_urls.txt"
cat "$OUTDIR/target_urls.txt" | cut -f1 | cut -d'/' -f3 | sort -u | grep -v '^http' | cut -d'"' -f1 > "$OUTDIR/domains.txt"
cat "$OUTDIR/target_urls.txt" | cut -f1 | cut -d'/' -f1-3 --complement | cut -d'?' -f1 | cut -d';' -f1 | awk -F'/' '{print $NF}' | sort -u > "$OUTDIR/filenames.txt"
cat "$OUTDIR/filenames.txt" | grep '\.' | awk -F'.' '{print $NF}' | sort -u > "$OUTDIR/file_extensions.txt"
rm "$OUTDIR/targets.txt" "$OUTDIR/urls.txt" "$OUTDIR/domains.txt" "$OUTDIR/filenames.txt"

# Sources of input
echo "# Sources of Input"
grep -e '?' -e $'\t[^[[:space:]]' "$OUTDIR/target_urls.txt" > "$OUTDIR/input.txt"
cut -f1 "$OUTDIR/input.txt" | cut -d'?' -f2 | sed 's/=[^&]*\(&\|$\)/\n/g' | grep -v '^$' | sort -u > "$OUTDIR/get_names.txt"
cut -f1 "$OUTDIR/input.txt" | cut -d'?' -f2 | tr '&' '\n' | sed 's/^[^=]*=//g' | grep -v ^$ | sort -u > "$OUTDIR/get_values.txt"
cut -f2 "$OUTDIR/input.txt" | sed 's/=[^&]*\(&\|$\)/\n/g' | grep -v '^$' | sort -u > "$OUTDIR/post_names.txt"
cut -f2 "$OUTDIR/input.txt" | tr '&' '\n' | sed 's/^[^=]*=//g' | grep -v ^$ | sort -u > "$OUTDIR/post_values.txt"
cat "$OUTDIR/get_names.txt" "$OUTDIR/post_names.txt" | sort -u > "$OUTDIR/parameter_names.txt"
cat "$OUTDIR/get_values.txt" "$OUTDIR/post_values.txt" | sort -u > "$OUTDIR/parameter_values.txt"
rm "$OUTDIR/get_names.txt" "$OUTDIR/get_values.txt" "$OUTDIR/post_names.txt" "$OUTDIR/post_values.txt"

# List any readable strings in Viewstate's parameters:
grep -o "__VIEWSTATE=[^&|$]*" "$OUTDIR/input.txt" | sed 's/__VIEWSTATE=//;s/&$//' | perl -pe 's/%([0-9a-f]{2})/sprintf("%s", pack("H2",$1))/eig' | base64 -d - | strings | sort -u > "$OUTDIR/viewstate_strings.txt"

# Sources of Input converted to Excel Table (very ugly)
sed 's_^https\?://\([^/]*\)/_\1\t/_;s_=[^&]*\(&\|$\|\t\)_\t_g;s/?/\t/g' "$OUTDIR/input.txt" | awk 'BEGIN {OFS="\t"} {print $1, $2, NF-2, "Pass/Fail"}' | sort -u | perl -lan -F'/\t/' -E 'if (@F[0] eq $h && @F[1] eq $s){if (@F[2]<$min){$min=@F[2]} elsif (@F[2]>$max){$max=@F[2]} }else{if ($h){if ($min==$max){$range=$min}else{$range="$min-$max"} say "$h\t$s\t$range\tCHECK"}$h=@F[0];$s=@F[1];$min=$max=@F[2]} END {if ($h){if ($min==$max){$range=$min}else{$range="$min-$max"} say "$h\t$s\t$range\tCHECK"}}' | grep -v -e '\.js[[:space:]]' -e '\.css[[:space:]]' | grep -f "$OUTDIR/targets.txt" > "$OUTDIR/input_table.txt"

# Server headers and names
echo "# Server Header and Names"
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v "substring-before(substring-after(../../info/response,'&#10;'),'&#10;&#10;')" -n "$PARSEDFILE" | grep -v '^$' | sort -u > "$OUTDIR/server_headers.txt"
cat "$OUTDIR/server_headers.txt" | grep -vi -e '^Content-Length:' -e '^Date:' -e '^Expires:' -e '^Last-Modified:' -e '^Location:' -e '^Set-Cookie:' | sort -u > "$OUTDIR/server_headers_unique.txt"
cat "$OUTDIR/server_headers.txt" | cut -d':' -f1 | sort -u > "$OUTDIR/header_names.txt"
cat "$OUTDIR/server_headers.txt" | grep -i '^Content-Type:' | cut -d':' -f2 | sed 's/^ *//' | sort -u > "$OUTDIR/content_types.txt"
cat "$OUTDIR/server_headers.txt" | grep -i 'set-cookie:' | cut -d':' -f2 | cut -d'=' -f1 | sed 's/^ //' | sort -u > "$OUTDIR/cookie_names.txt"
rm "$OUTDIR/server_headers.txt"

# Cookies sent to web browser
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v "substring-before(substring-after(../../info/request,'&#10;'),'&#10;&#10;')" -n "$PARSEDFILE" | grep -v '^$' | sort -u > "$OUTDIR/request_headers.txt"
grep -i '^ cookie:' "$OUTDIR/request_headers.txt" | sed 's/^cookie: //i;s/; /\n/g' | grep -v ^$ |sort -u > "$OUTDIR/sent_cookies.txt"
cat "$OUTDIR/request_headers.txt" | grep -vi -e '^Content-Length:' -e '^Content-Type: multipart' -e '^Cookie:' -e '^Referer:' | sort -u > "$OUTDIR/request_headers_unique.txt"

# Cookies matched to host (need to match all possible set-cookie case headers)
echo "# Cookies matched to host" # Catch all case possibilities of 'Set-Cookie:'
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v host -o ":" -v "substring-before(substring-after(substring-before(../../info/response,'&#10;&#10;'),'Set-Cookie: '),'&#10;')" -n "$PARSEDFILE" | grep -v ":$" | sort -u > "$OUTDIR/server_cookies.txt"
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v host -o ":" -v "substring-before(substring-after(substring-before(../../info/response,'&#10;&#10;'),'Set-cookie: '),'&#10;')" -n "$PARSEDFILE" | grep -v ":$" | sort -u >> "$OUTDIR/server_cookies.txt"
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v host -o ":" -v "substring-before(substring-after(substring-before(../../info/response,'&#10;&#10;'),'set-cookie: '),'&#10;')" -n "$PARSEDFILE" | grep -v ":$" | sort -u >> "$OUTDIR/server_cookies.txt"
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v host -o ":" -v "substring-before(substring-after(substring-before(../../info/response,'&#10;&#10;'),'SET-COOKIE: '),'&#10;')" -n "$PARSEDFILE" | grep -v ":$" | sort -u >> "$OUTDIR/server_cookies.txt"
egrep -i "aspsessionid|session_id|jsessionid|PHPSESSID|cfid|cftoken" "$OUTDIR/server_cookies.txt" > "$OUTDIR/session_cookies.txt"
egrep -i "aspsessionid|session_id|jsessionid|PHPSESSID|cfid|cftoken" "$OUTDIR/target_urls.txt" > "$OUTDIR/url_cookies.txt"
cat "$OUTDIR/server_cookies.txt" | process_HTTP_cookies.py | sort -u > "$OUTDIR/cookie_table.txt"
rm "$OUTDIR/server_cookies.txt"

# Extract all Server body content, and search for interesting strings
# We may not want to sort by lines.. in case we have multiline content...
echo "# Dumping all non-binary server body content to single file: '$OUTDIR/server_body.txt'"

# Non-base64 encoded content only, not sorted to keep multiline matches properly ordered
xmlstarlet sel -T -t -m "burp/state/target/item/url/service" -v "substring-after(../../info/response[not(@dt='dt:binary.base64')],'&#10;&#10;')" -n "$PARSEDFILE" > "$OUTDIR/server_body.txt"
echo "# Optimizing server body content for single-line matches: '$OUTDIR/server_body_sorted.txt'"
sed 's/^\s*//g;s/\s*$//g;s/\s+/ /g' "$OUTDIR/server_body.txt" | sort -u > "$OUTDIR/server_body_sorted.txt"

echo "# Content extracted from server body 1 of 3"
cat "$OUTDIR/server_body.txt" | perl -nle 'print $1 while /(<!--.*?-->)/g' | sed 's/<!--\s*//g;s/\s*-->//g' | sed -e 's/<[^>]*>//g' | grep -v ^$ | filter > "$OUTDIR/comments.txt"
cat "$OUTDIR/server_body.txt" | perl -nle 'print $1 while /(\/\*.*\*\/)/g' | sed 's/\/\*\s*//g;s/\s*\*\///g' | sed -e 's/<[^>]*>//g' | grep -v ^$ | filter >> "$OUTDIR/comments.txt"
grep "^\s*//" "$OUTDIR/server_body.txt" | sed 's_^.*//_//_g' | grep -v ^$ | filter >> "$OUTDIR/comments.txt"
cat "$OUTDIR/server_body.txt" | perl -nle 'print $1 while /(<meta.*?>)/ig' | sort -u >> "$OUTDIR/meta.txt"
cat "$OUTDIR/server_body.txt" | perl -nle 'print $1."\t" while /(https?:\/\/[^\(\)<>\"'\''\\,:;\s]+)/g' | sort -u | tr -d '\t' | grep -v -e "ssl\.$" -e "www\.$" | filter > "$OUTDIR/links.txt"
cat "$OUTDIR/server_body.txt" | egrep -o '[^`!%@\(\)<>\"'\'',;[:space:]]+@[^`!%@\(\)<>\"'\'',;[:space:]]+' | grep -ie "com" -e "net" -e "org" -e "\.[a-z]\{2,3\}$" | filter > "$OUTDIR/email.txt"
cat "$OUTDIR/server_body.txt" | egrep -o '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' | grep -e "^10\." -e "^192\.168\." -e "^172\." | sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 | filter > "$OUTDIR/internal_ip.txt"
cat "$OUTDIR/server_body.txt" | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | filter > "$OUTDIR/possible_ip.txt" 
cat "$OUTDIR/server_body.txt" | egrep -o -e 'C:\\[[:alnum:]\\]*' -e "/dev/[[:alnum:]/]*" -e "/etc/[[:alnum:]/]*" -e "/home/[[:alnum:]/]*" -e "/tmp/[[:alnum:]/]*" -e "/usr/[[:alnum:]\]*" -e "/var/[[:alnum:]/]*" | filter > "$OUTDIR/local_path.txt"
cat "$OUTDIR/server_body.txt" | egrep -i 'Error' | sed -e 's#<[^>]*>##g;s#^[ \t]*##g' | sort -u | grep -v -e 'var' -e '{' -e '^$' | filter > "$OUTDIR/error.txt"
cat "$OUTDIR/server_body.txt" | egrep -i -e "<\? " -e 'php ' -e 'perl ' -e'[^.]asp ' -e 'cfm ' -e 'VB ' | filter > "$OUTDIR/code.txt"
cat "$OUTDIR/server_body.txt" | sed 's/<[^>]*>//g' | perl -0777ne 's|<script.*?</script>||gms;print' | egrep -i -v -e "(function|var|if|else|return|switch|case|;|=)" -e "^\s*$" | tr -s '[:blank:]' ' ' | grep '[:alnum:]' | filter > "$OUTDIR/text.txt"
cat "$OUTDIR/text.txt" | tr -sc [:alnum:] '\n' | tr [A-Z] [a-z] | sort -u > "$OUTDIR/words.txt"
cat "$OUTDIR/server_body.txt" | perl -nle 'print $1 while /<(\w*)/g' | tr [:upper:] [:lower:] | grep -v ^$ | sort | uniq -c | sort -n | sed 's/^\s*//' > "$OUTDIR/html_tags.txt"
cat "$OUTDIR/server_body.txt" | perl -nle 'print $1 while /function (\w+\s*\([^)]*\))/g' | filter  > "$OUTDIR/js_functions.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'location\.search' | sed 's/^\s*//;s/\s*$//' | filter > "$OUTDIR/js_query_access.txt"
cat "$OUTDIR/server_body.txt" | grep 'eval\s*(' | sed 's/^\s*//;s/\s*$//' | filter > "$OUTDIR/js_eval.txt"
cat "$OUTDIR/server_body.txt" | grep "\.js" | egrep -io "(\w|/)+\.js" | filter > "$OUTDIR/js_files.txt"
cat "$OUTDIR/server_body.txt" | grep "\.css" | egrep -io "(\w|/)+\.css" | filter > "$OUTDIR/css_files.txt"
grep -i 'upload' "$OUTDIR/server_body.txt" | filter > "$OUTDIR/uploads.txt"

echo "# Content extracted from server body 2 of 3"
cat "$OUTDIR/server_body.txt" | grep -i -e 'java[^s]' -e 'applet' | filter > "$OUTDIR/java_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'activex' | perl -nle 'print $1 while /^(.{0,100}activex.{0,100})$/ig' | grep -v "Microsoft.XMLHTTP" | filter > "$OUTDIR/activex_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'hidden' | filter > "$OUTDIR/hidden_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'secret' | filter > "$OUTDIR/secret_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'password' | filter > "$OUTDIR/password_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'AllowScriptAccess="always"' | sort -u > "$OUTDIR/AllowScriptAccess.txt"
cat "$OUTDIR/server_body.txt" | grep -i 'autocomplete="on"' | sort -u > "$OUTDIR/autocomplete_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "authoriz" -e "password" -e "passcode" -e "pwd" -e "access" -e "cred" -e "secure" -e "secret" | filter > "$OUTDIR/credentials.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e 'WWW-Authenticate' | filter > "$OUTDIR/http_auth.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "insert into" -e "order by" -e "SQL" -e "SELECT \* FROM" | filter > "$OUTDIR/sql_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "userAgent" -e "Browser" -e "MSIE" -e "Mozilla" -e "Firefox" -e "gecko" -e "Opera" -e "Chrome" -e "Safari" -e "WebKit" -e "Konqueror" -e "Netscape" -e "Lynx" -e "Curl" -e "wget" -e "WebTV" | perl -nle 'print $1 while /^(.{0,100}(userAgent|Browser|MSIE|Firefox|gecko|Opera |Chrome|Safari|WebKit|Konqueror|Netscape|Lynx|Curl|wget|WebTV).{0,100})$/ig' | filter > "$OUTDIR/browser_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "XP" -e "3.1" -e "2k" -e "2k3" -e "Vista" -e "Linux" -e "Unix" -e "Ubuntu" -e "Apple" -e "Mac" -e "Macintosh" -e "OSX" -e "Solaris" -e "BSD" -e "Wii" -e "XBOX" -e "PS3" | filter > "$OUTDIR/os_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i cookie | filter > "$OUTDIR/cookie_references.txt"
grep -f "$OUTDIR/cookie_names.txt" "$OUTDIR/server_body.txt" | filter > "$OUTDIR/cookie_name_references.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "flash" -e "silverlight" -e "Adobe" -e "acrobat" | filter > "$OUTDIR/third_party.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e 'document\.location' -e 'document\.URL' -e 'document\.referrer' -e 'document\.URLUnencoded' -e 'window\.location' | filter > "$OUTDIR/js_read.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e 'document\.write' -e 'document\.writeln' -e 'document\.body\.innerHtml' -e 'document\.attachEvent' -e 'document\.create' -e 'document\.execCommand' -e 'window\.attachEvent' -e 'document\.location' -e 'document\.location\.hostname' -e 'document\.location\.replace' -e 'document\.location\.assign' -e 'document\.URL' -e 'window\.navigate' -e 'document\.open' -e 'window\.open' -e 'window\.location\.href' -e 'eval' -e 'window\.execScript' -e 'window\.setInterval' -e 'window\.setTimeout' | sort -u > "$OUTDIR/js_write.txt"

echo "# Content extracted from server body 3 of 3"
cat "$OUTDIR/server_body.txt" | grep -i -e 'telnet' -e 'ftp' -e 'ssh' -e 'smb' -e "pop" -e "smtp" -e "://" | grep -iv -e 'http' | filter > "$OUTDIR/protocols.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "XXX" -e "todo" -e "fix" -e "to do" -e "problem" -e "not work" -e "frustrate" -e "dumb" -e "stupid" -e "shit" -e "fuck" -e "bitch" -e "ARGH" -e 'issue' -e 'CVE' -e 'BID' | filter > "$OUTDIR/code_issues.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e "encypt" -e "md5" -e "sha" -e "hash" -e "encode" | filter > "$OUTDIR/encryption.txt"
cat "$OUTDIR/server_body.txt" | grep -i -e 'credit card' -e 'visa' -e 'mastercard' -e 'american express' -e "diners card" -e "paypal" -e "google checkout" | filter > "$OUTDIR/ccn.txt"

# Pass through fuzzdb's list of regexes
grep -F -f errors.txt "$OUTDIR/server_body.txt" | filter > "$OUTDIR/fuzzdb_errors.txt"
grep -E -f pii.fuzz.txt "$OUTDIR/server_body.txt" | filter > "$OUTDIR/fuzzdb_pii.txt"

# Delete unnecessary and empty files
echo "# Removing unnecessary and empty files"
#rm "$OUTDIR/burp.xml" "$OUTDIR/server_body.txt" "$OUTDIR/server_body_sorted.txt"
find "$OUTDIR" -maxdepth 1 -empty -delete

echo "# Burp session file analysis complete in $OUTDIR"
