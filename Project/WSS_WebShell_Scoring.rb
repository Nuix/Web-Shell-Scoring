# Scores text based on rules.
# Adds custom metadata "WebShell Score"
def nuix_worker_item_callback(worker_item)
  rules = {
    'Copyright \\(c\\) 1997-2010 The PHP Group' => -200,
    'eval\\(' => 25,
    'base64_decode\\(' => 25,
    'gzinflate' => 25,
    'passthru\\(' => 25,
    'proc_open\\(' => 25,
    'system\\(' => 25,
    'shell_exec\\(' => 25,
    'cfexecute' => 25,
    'cmd.exe' => 25,
    'runcommand' => 25,
    'mdEncode' => 25,
    'zaco' => 25,
    'zippo' => 25,
    'XiX_' => 25,
    'Nuke Shell' => 25,
    'Reverse Shell' => 25,
    'cleanCC\\(' => 25,
    'r57sh' => 25,
    'c99sh' => 25,
    'uZE Shell' => 25,
    'TC9A16C47DA8EEE87' => 50,
    'webshell' => 25,
    'Nickserv.*identify' => 50,
    'laudanum' => 50,
    'web shell' => 25,
    '0rb' => 25,
    'orb' => 25,
    'SQL Dumper' => 100,
    '\\\\x70\\\\x72\\\\x65\\\\x67\\\\x5f\\\\x72\\\\x65\\\\x70\\\\x6c\\\\x61\\\\x63\\\\x65' => 100,
    '\\\\x65\\\\x76\\\\x61\\\\x6C' => 100,
    '\\\\x28\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36' => 100
  }

  source_item = worker_item.source_item
  type = source_item.get_type.get_name
  begin
    if type =~ /text/ || type =~ /script/
      data = source_item.get_text.to_string
      score = 0
      rules.each { |k, v| score += v if data =~ /#{k}/i }
      worker_item.add_custom_metadata('WebShell Score', score, 'integer', 'user')
    end
  rescue StandardError
    return
  end
end
