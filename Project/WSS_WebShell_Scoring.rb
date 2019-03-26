# Scores text based on rules.
# Adds custom metadata "WebShell Score"

TYPES = [/text/, /script/].freeze
RULES = {
  /Copyright \(c\) 1997-2010 The PHP Group/i => -200,
  /eval\(/i => 25,
  /base64_decode\(/i => 25,
  /gzinflate/i => 25,
  /passthru\(/i => 25,
  /proc_open\(/i => 25,
  /system\(/i => 25,
  /shell_exec\(/i => 25,
  /cfexecute/i => 25,
  /cmd.exe/i => 25,
  /runcommand/i => 25,
  /mdEncode/i => 25,
  /zaco/i => 25,
  /zippo/i => 25,
  /XiX_/i => 25,
  /Nuke Shell/i => 25,
  /Reverse Shell/i => 25,
  /cleanCC\(/i => 25,
  /r57sh/i => 25,
  /c99sh/i => 25,
  /uZE Shell/i => 25,
  /TC9A16C47DA8EEE87/i => 50,
  /webshell/i => 25,
  /Nickserv.*identify/i => 50,
  /laudanum/i => 50,
  /web shell/i => 25,
  /0rb/i => 25,
  /orb/i => 25,
  /SQL Dumper/i => 100,
  /\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65/i => 100,
  /\\x65\\x76\\x61\\x6C/i => 100,
  /\\x28\\x62\\x61\\x73\\x65\\x36/i => 100
}.freeze

def nuix_worker_item_callback(worker_item)
  source_item = worker_item.source_item
  type = source_item.get_type.get_name
  return nil unless TYPES.any? { |t| type =~ t }

  begin
    score = score_text(source_item.get_text.to_string)
    worker_item.add_custom_metadata('WebShell Score', score, 'integer', 'user')
  rescue StandardError
    return
  end
end

def score_text(text)
  score = 0
  RULES.each { |k, v| score += v if text =~ k }
  score
end
