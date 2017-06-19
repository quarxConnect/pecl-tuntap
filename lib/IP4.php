<?PHP

  class IP4_Frame implements Ethernet_Protocol {
    const PROTOCOL_NUMBER = 0x0800;
    
    const FLAG_DONT_FRAGMENT = 0x02;
    const FLAG_HAS_FRAGMENTS = 0x04;
    
    private static $Protocols = array ();
    
    private $ipVersion = 0x0;
    private $ipHeaderLength = 0x0;
    private $ipTypeOfService = 0x00;
    private $ipLength = 0x0000;
    private $ipID = 0x0000;
    private $ipFlags = 0x0;
    private $ipFragmentOffset = 0x0000;
    private $ipTimeToLive = 0x00;
    private $ipProtocol = 0x00;
    private $ipChecksum = 0x0000;
    private $ipValidatedChecksum = 0x0000;
    private $ipSourceAddress = 0x00000000;
    private $ipTargetAddress = 0x00000000;
    private $ipPayload = '';
    
    // {{{ registerProtocol
    /**
     * Register handler for a Layer-4 Protocol
     * 
     * @param int $Number
     * @param string $Description
     * @param string $Classname
     * 
     * @access public
     * @return void
     **/
    public static function registerProtocol ($Number, $Description, $Classname) {
      self::$Protocols [$Number] = array ($Description, $Classname);
    }
    // }}}
    
    // {{{ parse
    /**
     * Try to parse data from an IPv4-Frame into this object
     * 
     * @param string $Data
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data) {
      // Check length of data
      if (($Length = strlen ($Data)) < 20) {
        trigger_error ('IPv4-Frame too short');
        
        return false;
      }
      
      // Parse default header
      $Byte = ord ($Data [0]);
      $ipVersion = (($Byte >> 4) & 0xF);
      $ipHeaderLength = ($Byte & 0xF);
      
      if ($ipVersion != 4) {
        trigger_error ('IP-Frame is version ' . $ipVersion . ', NOT IPv4');
        
        return false;
      } elseif (($ipHeaderLength < 5) || ($ipHeaderLength * 4 > $Length)) {
        trigger_error ('IPv4-Frame too short for header');
        
        return false;
      }
      
      $ipTypeOfService = ord ($Data [1]);
      $ipLength = (ord ($Data [2]) << 8) | ord ($Data [3]);
      $ipID = (ord ($Data [4]) << 8) | ord ($Data [5]);
      
      
      if ($Length < $ipLength) {
        trigger_error ('IPv4-Frame size mismatch');
        
        return false;
      }
      
      $ipCSum = (($Byte << 8) | $ipTypeOfService) + $ipLength + $ipID;
      
      $Byte = ord ($Data [6]);
      $ipFlags = (($Byte >> 5) & 0x7);
      
      if ($ipFlags & 0x01) {
        trigger_error ('IPv4-Frame has invalid Flags');
        
        return false;
      }
      
      $ipFragmentOffset = (($Byte & 0x1F) << 8) | ord ($Data [7]);
      $ipTimeToLive = ord ($Data [8]);
      $ipProtocol = ord ($Data [9]);
      $ipChecksum = (ord ($Data [10]) << 8) | ord ($Data [11]);
      $ipSourceAddress = (ord ($Data [12]) << 24) | (ord ($Data [13]) << 16) | (ord ($Data [14]) << 8) | ord ($Data [15]);
      $ipTargetAddress = (ord ($Data [16]) << 24) | (ord ($Data [17]) << 16) | (ord ($Data [18]) << 8) | ord ($Data [19]);
      
      $ipCSum +=
        (($Byte << 8) | ($ipFragmentOffset & 0xFF)) +
        (($ipTimeToLive << 8) | $ipProtocol) +
        (($ipSourceAddress >> 16) & 0xFFFF) + ($ipSourceAddress & 0xFFFF) +
        (($ipTargetAddress >> 16) & 0xFFFF) + ($ipTargetAddress & 0xFFFF);
      
      # TODO: Parse additional headers
      
      // Validate Checksum
      for ($p = 20; $p < $ipHeaderLength * 4; $p += 2)
        $ipCSum += (ord ($Data [$p]) << 8) | ord ($Data [$p + 1]);
      
      $ipCSum = (~(($ipCSum & 0xFFFF) + (($ipCSum >> 16) & 0xFFFF)) & 0xFFFF);
      
      // Process Frame-Payload
      $ipPayload = substr ($Data, $ipHeaderLength * 4);
      
      if (isset (self::$Protocols [$ipProtocol])) {
        $Classname = self::$Protocols [$ipProtocol][1];
        $Class = new $Classname;
        
        if ($Class->parse ($ipPayload))
          $ipPayload = $Class;
      }
      
      // Copy parsed value to our object
      $this->ipVersion = $ipVersion;
      $this->ipHeaderLength = $ipHeaderLength;
      $this->ipTypeOfService = $ipTypeOfService;
      $this->ipLength = $ipLength;
      $this->ipID = $ipID;
      $this->ipFlags = $ipFlags;
      $this->ipFragmentOffset = $ipFragmentOffset;
      $this->ipTimeToLive = $ipTimeToLive;
      $this->ipProtocol = $ipProtocol;
      $this->ipChecksum = $ipChecksum;
      $this->ipValidatedChecksum = $ipCSum;
      $this->ipSourceAddress = $ipSourceAddress;
      $this->ipTargetAddress = $ipTargetAddress;
      $this->ipPayload = $ipPayload;
      
      return true;
    }
    // }}}
    
    // {{{ process
    /**
     * Process this IPv4-Frame
     * 
     * @access public
     * @return object
     **/
    public function process () {
      // Check if we have to care about the frame
      global $virtualIP4;
      
      if ($this->ipTargetAddress != ip2long ($virtualIP4))
        return;
      
      // Check if we have a Layer-4 Handler
      if (!is_object ($this->ipPayload))
        return;
      
      // Call the layer-4 handler
      if (!is_object ($Response = $this->ipPayload->process ()))
        return;
      
      if ($Response instanceof IP4_Frame)
        return $Response;
      
      // Prepare a response-frame
      $Frame = new $this;
      $Frame->ipSourceAddress = $this->ipTargetAddress;
      $Frame->ipTargetAddress = $this->ipSourceAddress;
      $Frame->ipTimeToLive = 64;
      
      # TODO: What about the other fields here?!
      
      $Frame->ipProtocol = $Response::PROTOCOL_NUMBER;
      $Frame->ipPayload = $Response;
      
      return $Frame;
    }
    // }}}
    
    // {{{ dump
    /**
     * Create a binary dump of this frame
     * 
     * @access public
     * @return string
     **/
    public function dump () {
      // Prepare our payload
      $Payload = (is_object ($this->ipPayload) ? $this->ipPayload->dump () : $this->ipPayload);
      $Length = strlen ($Payload) + 20;
      
      // Prepare header-checksum
      $ipChecksum =
        (0x4500 | ($this->ipTypeOfService & 0xFF)) +
        ($Length & 0xFFFF) + 
        ($this->ipID & 0xFFFF) +
        ((($this->ipFlags & 0x07) << 13) | $this->ipFragmentOffset & 0x1FFF) +
        ((($this->ipTimeToLive & 0xFF) << 8) | ($this->ipProtocol & 0xFF)) +
        (($this->ipSourceAddress >> 16) & 0xFFFF) + ($this->ipSourceAddress & 0xFFFF) +
        (($this->ipTargetAddress >> 16) & 0xFFFF) + ($this->ipTargetAddress & 0xFFFF);
      
      # TODO: Add words from additional headers
      
      $ipChecksum = (~(($ipChecksum & 0xFFFF) + (($ipChecksum >> 16) & 0xFFFF)) & 0xFFFF);
      
      // Output the frame
      return
        "\x45" . chr ($this->ipTypeOfService & 0xFF) .
        chr (($Length >> 8) & 0xFF) . chr ($Length & 0xFF) .
        chr (($this->ipID >> 8) & 0xFF) . chr ($this->ipID & 0xFF) .
        chr ((($this->ipFlags & 0x07) << 5) | (($this->ipFragmentOffset >> 8) & 0x1F)) . chr ($this->ipFragmentOffset & 0xFF) .
        chr ($this->ipTimeToLive & 0xFF) . chr ($this->ipProtocol & 0xFF) .
        chr (($ipChecksum >> 8) & 0xFF) . chr ($ipChecksum & 0xFF) .
        chr (($this->ipSourceAddress >> 24) & 0xFF) . chr (($this->ipSourceAddress >> 16) & 0xFF) . chr (($this->ipSourceAddress >> 8) & 0xFF) . chr ($this->ipSourceAddress & 0xFF) .
        chr (($this->ipTargetAddress >> 24) & 0xFF) . chr (($this->ipTargetAddress >> 16) & 0xFF) . chr (($this->ipTargetAddress >> 8) & 0xFF) . chr ($this->ipTargetAddress & 0xFF) .
        $Payload;
    }
    // }}}
    
    // {{{ outputDebug
    /**
     * Output debug-information for this IPv4-Frame
     * 
     * @access public
     * @return void
     **/
    public function outputDebug () {
      printf (
        '  IPv4 %s > %s TOS 0x%02X ID %04X Flags %s TTL %d Offset %d Proto %s (0x%04X) Length %d Payload %d' . "\n",
        long2ip ($this->ipSourceAddress),
        long2ip ($this->ipTargetAddress),
        $this->ipTypeOfService,
        $this->ipID,
        decbin ($this->ipFlags),
        $this->ipTimeToLive,
        $this->ipFragmentOffset,
        (isset (self::$Protocols [$this->ipProtocol]) ? self::$Protocols [$this->ipProtocol][0] : 'Unknown'),
        $this->ipProtocol,
        $this->ipLength,
        $this->ipLength - ($this->ipHeaderLength * 4)
      );
      
      if ($this->ipChecksum != $this->ipValidatedChecksum)
        printf ('  Invalid IPv4 Checksum: 0x%04X on frame, 0x%04X calculated' . "\n", $this->ipChecksum, $this->ipValidatedChecksum);
      
      if (is_object ($this->ipPayload))
        $this->ipPayload->outputDebug ();
    }
    // }}}
  }
  
  class IP4_ICMP_Frame implements Ethernet_Protocol {
    const PROTOCOL_NUMBER = 0x01;
    
    const TYPE_ECHO_REPLY = 0x00;
    const TYPE_ECHO_REQUEST = 0x08;
    
    private $icmpType = 0x00;
    private $icmpCode = 0x00;
    private $icmpChecksum = 0x0000;
    private $icmpValidatedChecksum = 0x0000;
    private $icmpPayload = null;
    
    // {{{ parse
    /**
     * Parse an ICMP-Message into this object
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data) {
      // Check if the message is long enough
      if (($Length = strlen ($Data)) < 4) {
        trigger_error ('ICMPv4-Frame too short');
        
        return false;
      }
      
      // Read all values
      $this->icmpType = ord ($Data [0]);
      $this->icmpCode = ord ($Data [1]);
      $this->icmpChecksum = (ord ($Data [2]) << 8) | ord ($Data [3]);
      $this->icmpPayload = ($Length > 4 ? substr ($Data, 4) : null);
      
      // Validate the checksum
      $this->icmpValidatedChecksum =
        (($this->icmpType << 8) | $this->icmpCode);
      
      for ($p = 0; $p < $Length - 4; $p += 2)
        $this->icmpValidatedChecksum += ((ord ($this->icmpPayload [$p]) << 8) | ord ($this->icmpPayload [$p + 1]));
      
      $this->icmpValidatedChecksum = (~(($this->icmpValidatedChecksum & 0xFFFF) + (($this->icmpValidatedChecksum >> 16) & 0xFFFF)) & 0xFFFF);
      
      // Indicate success
      return true;
    }
    
    // {{{ process
    /**
     * Process this ICMP-Frame
     * 
     * @access public
     * @return object
     **/
    public function process () {
      // Check wheter to response to an echo-request
      if ($this->icmpType == self::TYPE_ECHO_REQUEST) {
        $Response = clone $this;
        $Response->icmpType = self::TYPE_ECHO_REPLY;
        
        return $Response;
      }
    }
    // }}}
    
    // {{{ dump
    /**
     * Create a binary dump of this frame
     * 
     * @access public
     * @return string
     **/
    public function dump () {
      // Generate checksum for the output
      $icmpChecksum = (($this->icmpType << 8) | $this->icmpCode);
      
      for ($p = 0; $p < strlen ($this->icmpPayload); $p += 2)
        $icmpChecksum += ((ord ($this->icmpPayload [$p]) << 8) | ord ($this->icmpPayload [$p + 1]));
                    
      $icmpChecksum = (~(($icmpChecksum & 0xFFFF) + (($icmpChecksum >> 16) & 0xFFFF)) & 0xFFFF);
      
      // Dump the frame
      return
        chr ($this->icmpType & 0xFF) .
        chr ($this->icmpCode & 0xFF) .
        chr (($icmpChecksum >> 8) & 0xFF) . chr ($icmpChecksum & 0xFF) .
        $this->icmpPayload;
    }
    // }}}
    
    // {{{ outputDebug
    /**
     * Output debug-information for this frame
     * 
     * @access public
     * @return void
     **/
    public function outputDebug () {
      printf ('    ICMP Type 0x%02X Code 0x%02X Checksum 0x%04X Payload %d' . "\n", $this->icmpType, $this->icmpCode, $this->icmpChecksum, strlen ($this->icmpPayload));
      
      if ($this->icmpChecksum != $this->icmpValidatedChecksum)
        printf ('    Invalid ICMP Checksum: 0x%04X on frame, 0x%04X calculated' . "\n", $this->icmpChecksum, $this->icmpValidatedChecksum);
    }
    // }}}
  }
  
  // ICMP is treated as Layer-3 Protocol, altough it is encapsulated inside IPv4
  IP4_Frame::registerProtocol (IP4_ICMP_Frame::PROTOCOL_NUMBER, 'ICMP', 'IP4_ICMP_Frame');
  
  // Register IPv4 at Layer 2
  if (class_exists ('Ethernet_Frame'))
    Ethernet_Frame::registerProtocol (IP4_Frame::PROTOCOL_NUMBER, 'IPv4', 'IP4_Frame');

?>