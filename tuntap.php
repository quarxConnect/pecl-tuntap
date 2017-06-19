<?PHP

  error_reporting (E_ALL);
  
  // Construct a line-break for outputs
  $br = ((php_sapi_name () == 'cli') ? '' : '<br />');
  
  // Make sure the extension is loaded
  $module = 'tuntap';
  
  if (!extension_loaded ($module))
    @dl ($module . '.' . PHP_SHLIB_SUFFIX);
  
  if (!extension_loaded ($module))
    die ('Module ' . $module . ' is not compiled/loaded into PHP' . "\n");
  
  // Output summary of available functions on the extension
  $functions = get_extension_funcs ($module);
  
  echo 'Functions available in the test extension:', $br, "\n";
  
  foreach ($functions as $func)
    echo '  ', $func, $br, "\n";
  
  echo $br, "\n";
  
  /**
   * Ethernet Frames
   * 
   * V2		Preamble SFD Dest[6] Src[6]  Type[2]                                      Payload[.] FCS[4]
   * 802.3r	Preamble SFD Dest[6] Src[6]  Length[2] Byte[=]                            Payload[.] FCS[4]
   * 802.2	Preamble SFD Dest[6] Src[6]  Length[2] DSAP[1]   SSAP[1] Ctrl[1]          Payload[.] FCS[4]
   * 802.2s	Preamble SFD Dest[6] Src[6]  Length[2] DSAP[=]   SSAP[=] Ctrl[=] SNAP[5]  Payload[.] FCS[4]
   * V2t	Preamble SFD Dest[6] Src[6]  Tag[4]    Type[2]                            Payload[.] FCS[4]
   * 802.2t	Preamble SFD Dest[6] Src[6]  Tag[4]    Length[2] DSAP[1] SSAP[1] Ctrl[1]  Payload[.] FCS[4]
   * 
   * SFD == 10101010
   *   V2:  Type>1500
   *   V2t: Tag[2] == 0x8100
   * SFD == 10101011
   *   802.3r: IPX only, Byte == 0xFFFF
   *   802.3:  
   *   802.3s: DSAP == 0xAA, SSAP == 0xAA, Ctrl == 0x03
   *   802.3t: Tag[2] == 0x8100
   * 
   * Preamble, SFD and FCS not present on TAP-Devices!
   **/
  
  /**
   * 0e:b2:91:d4:e9:f3 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Request who-has 10.0.0.2 tell 10.0.0.1, length 28
   *           Flags Proto Dest_____________ Src______________
   * 0x0000    00 00 08 06 ff ff ff ff ff ff 0e b2 91 d4 e9 f3    |................|
               Type_ HW___ Proto HA PA OP___ ARP-Src__________
   * 0x0010    08 06 00 01 08 00 06 04 00 01 0e b2 91 d4 e9 f3    |................|
   *           Tell-IP___  ARP-Dest-MAC_____ Who-Has-IP_
   * 0x0020    0a 00 00 01 00 00 00 00 00 00 0a 00 00 02          |..............|
   **/
  
  function run_command ($Command) {
    echo '+ ', $Command, "\n";
    
    $rc = 0;
    
    passthru ($Command, $rc);
    
    if ($rc != 0)
      echo '+ Command returned ', $rc, "\n";
    
    return ($rc == 0);
  }
  
  // Try to create a new TAP-Device
  if (!is_resource ($TAP = tuntap_new (null, TUNTAP_DEVICE_TAP)))
    die ('Failed to create TAP-Device' . "\n");
  
  $Interface = tuntap_name ($TAP);
  
  echo 'Created ', $Interface, "\n";
  
  run_command ('ip link set ' . $Interface . ' up');
  run_command ('ip addr add 10.10.10.1/24 dev ' . $Interface);
  
  // Read Frames from the device
  echo 'Waiting for frames...', $br, "\n";
  
  $virtualMAC = hex2bin ('020408163264');
  $virtualARP = array ();
  $virtualIP4 = '10.10.10.2';
  
  require_once ('lib/Ethernet.php');
  require_once ('lib/TAP.php');
  require_once ('lib/ARP.php');
  require_once ('lib/IP4.php');
  
  while (!feof ($TAP)) {
    // Try to read next frame from device
    if (($Data = fread ($TAP, 1522)) === false)
      die ('Failed to read frame' . "\n");
    
    // Create a new TAP-Frame
    $Frame = new TAP_Frame;
    
    // Try to parse the frame
    if (!$Frame->parse ($Data))
      continue;
    
    // Output debug-Information
    echo date ('H:i:s.u ');
    
    $Frame->outputDebug ();
    
    // Check if the frame is for us
    $Addr = $Frame->getDestinationAddress ();
    
    if (($Addr != $virtualMAC) && ($Addr != $Frame::BROADCAST_ADDRESS))
      continue;
    
    // Try to generate a response
    if (!is_object ($Response = $Frame->process ()))
      continue;
    
    $Response->setSourceAddress ($virtualMAC);
    $Data = $Response->dump ();
    # $Response->parse ($Data);
    
    // Output the response
    echo date ('H:i:s.u ');
    $Response->outputDebug ();
    
    // Write to the wire
    fwrite ($TAP, $Data);
  }
  
  fgets (STDIN);

?>
