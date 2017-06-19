<?PHP

  class Ethernet_Frame {
    const ETHER_FRAME_V2 = 0;
    const ETHER_FRAME_802 = 1;
    const ETHER_FRAME_802_RAW = 2;
    const ETHER_FRAME_802_SNAP = 3;
    
    const BROADCAST_ADDRESS = "\xff\xff\xff\xff\xff\xff";
    
    private static $Protocols = array (
      0x8137 => array ('IPX', 'IPX_Frame'),
      0x86DD => array ('IPv6', 'IP6_Frame'),
    );
    
    private $etherLength = 0;
    private $etherSrc = '';
    private $etherDst = '';
    private $etherFrameType = Ethernet_Frame::ETHER_FRAME_V2;
    private $etherProtoType = 0x0000;
    private $etherOUID = null;
    private $ether802DSAP = null;
    private $ether802SSAP = null;
    private $ether802Control = null;
    private $etherPayload = ''; 
    
    private $vlanID = null;
    private $vlanPriority = null;
    private $vlanCanonical = false;
    
    // {{{ registerProtocol
    /**
     * Register handler for a Layer-3 Protocol
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
    
    // {{{ getProtocolName
    /**
     * Retrive the name of a registered Layer-3 Protocol
     * 
     * @param int $Number
     * 
     * @access public
     * @return string
     **/
    public static function getProtocolName ($Number) {
      if (isset (self::$Protocols [$Number]))
        return self::$Protocols [$Number][0];
    }
    // }}}
    
    // {{{ getProtocolAddress
    /**
     * Try to retrive a representation for a Layer-3-Protocol-Address
     * 
     * @param int $Number
     * @param string $Address
     * @param bool $Human (optional)
     * 
     * @access public
     * @return mixed
     **/
    public static function getProtocolAddress ($Number, $Address, $Human = false) {
      // Hardcoded IPv4
      if ($Number == 0x0800) {
        if ($Human)
          return ord ($Address [0]) . '.' . ord ($Address [1]) . '.' . ord ($Address [2]) . '.' . ord ($Address [3]);
        
        return (ord ($Address [0]) << 24) | (ord ($Address [1]) << 16) | (ord ($Address [2]) << 8) | ord ($Address [3]);
      }
      
      if ($Human)
        return bin2hex ($Address);
    }
    // }}}
    
    // {{{ getReadableMAC
    /**
     * Make a MAC-Address more human-friendly
     * 
     * @param string $MAC
     * 
     * @access public
     * @return string
     **/
    public static function getReadableMAC ($MAC) {
      $Output = '';
      
      for ($i = 0; $i < strlen ($MAC); $i++)
        $Output .= sprintf ('%s%02X', ($i > 0 ? ':' : ''), ord ($MAC [$i]));
      
      return $Output;
    }
    // }}}
    
    // {{{ parse
    /**
     * Try to parse an entire ethernet-frame into this object
     * 
     * @param string $Data
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data) {
      // Map SAP-Protocols to "real" Protocols
      static $sapMap = array (
        0x06 => 0x0800,
        0x98 => 0x0806,
        0xE0 => 0x8137,
      );
      
      // Check the length of the frame
      if (($Length = strlen ($Data)) < 14) {
        trigger_error ('Ethernet-Frame too short');
        
        return false;
      }
      
      // Read Ethernet-Addresses
      $etherDst = substr ($Data, 0, 6);
      $etherSrc = substr ($Data, 6, 6);
      
      // Auto-Detect Frame-type
      $Detect = (ord ($Data [12]) << 8) | ord ($Data [13]);
      $Position = 14;
      
      // Check for VLAN-Tag / 802.1q
      if ($Detect == 0x8100) {
        // Check the length again
        if ($Length < 18) {
          trigger_error ('Ethernet-Frame (with VLAN) too short');
          
          return false;
        }
        
        // Extract the VLAN-Tag
        $Tag = (ord ($Data [14]) << 8) | ord ($Data [15]);
        $vlanPriority = (($Tag >> 13) & 0x0E);
        $vlanCanonical = ((($Tag >> 12) & 0x01) == 0x01);
        $vlanID = ($Tag & 0x0FFF);
        
        // Move forward with detection
        $Detect = (ord ($Data [16]) << 8) | ord ($Data [17]);
        $Position = 18;
      } else
        $vlanPriority = $vlanCanonical = $vlanID = null;
      
      // Must be a Length / 802.2 LLC Frame / 802.3r Frame
      if ($Detect < 1500) {
        // Check the length again
        if ($Length < $Position + 2) {
          trigger_error ('Ethernet-Frame with length too short');
          
          return false;
        }
        
        // Extract DSAP / SSAP from Frame
        $ether802DSAP = ord ($Data [$Position++]);
        $ether802SSAP = ord ($Data [$Position++]);
        
        // Detect 802.3r Frame
        if (($DSAP == 0xFF) && ($SSAP == 0x0FF)) {
          $etherFrameType = $this::ETHER_FRAME_802_RAW;
          $etherProtoType = 0x8137;
          $etherOUID = $ether802DSAP = $ether802SSAP = $ether802Control = null;
        
        // Check if there is enough data for control-byte
        } elseif ($Length < $Position + 1) {
          trigger_error ('Ethernet-Frame is missing control-byte');
          
          return false;
        
        // Any 802.2-Frame
        } else {
          // Extract Control-Byte
          $ether802Control = ord ($Data [$Position++]);
          
          // Detect 802.2s
          if (($ether802DSAP == 0xAA) && ($ether802SSAP == 0xAA) && ($ether802Control == 0x03)) {
            // Check the length
            if ($Length < $Position + 5) {
              trigger_error ('Ethernet-Frame 802.2s too short');
              
              return false;
            }
            
            $etherFrameType = $this::ETHER_FRAME_802_SNAP;
            $etherOUID = (ord ($Data [$Position++]) << 16) | (ord ($Data [$Position++]) << 8) | ord ($Data [$Position++]);
            $etherProtoType = (ord ($Data [$Position++]) <<  8) |  ord ($Data [$Position++]);
            $ether802DSAP = $ether802SSAP = $ether802Control = null;
            
          // Must be "normal" 802.3
          } else {
            # TODO: Is this really an error?!
            if (!isset ($sapMap [$DSAP])) {
              trigger_error ('Unknown DSAP');
              
              return false;
            }
            
            $etherFrameType = $this::ETHER_FRAME_802;
            $etherProtoType = $sapMap [$DSAP];
            $etherOUID = null;
          }
        }
          
      // Must be a type
      } else {
        $etherFrameType = $this::ETHER_FRAME_V2;
        $etherProtoType = $Detect;
        $etherOUID = $ether802DSAP = $ether802SSAP = $ether802Control = null;
      }
      
      // Handle the payload
      $etherPayload = substr ($Data, $Position);
      
      if (isset (self::$Protocols [$etherProtoType]) && class_exists (self::$Protocols [$etherProtoType][1])) {
        $Classname = self::$Protocols [$etherProtoType][1];
        $Class = new $Classname;
        
        if ($Class->parse ($etherPayload))
          $etherPayload = $Class;
      }
      
      // Copy the result
      $this->etherLength = $Length;
      $this->etherDst = $etherDst;
      $this->etherSrc = $etherSrc;
      $this->etherFrameType = $etherFrameType;
      $this->etherProtoType = $etherProtoType;
      $this->etherOUID = $etherOUID;
      $this->ether802DSAP = $ether802DSAP;
      $this->ether802SSAP = $ether802SSAP;
      $this->ether802Control = $ether802Control;
      $this->etherPayload = $etherPayload;
      
      $this->vlanPriority = $vlanPriority;
      $this->vlanCanonical = $vlanCanonical;
      $this->vlanID = $vlanID;
      
      // Indicate success
      return true;
    }
    // }}}
    
    // {{{ getSourceAddress
    /**
     * Retrive the source-address from this ethernet-frame
     * 
     * @param bool $Human (optional)
     * 
     * @access public
     * @return string
     **/
    public function getSourceAddress ($Human = false) {
      return ($Human ? $this::getReadableMAC ($this->etherSrc) : $this->etherSrc);
    }
    // }}}
    
    // {{{ setSourceAddress
    /**
     * Set a new source-address for this frame
     * 
     * @param string $Address
     * 
     * @access public
     * @return bool
     **/
    public function setSourceAddress ($Address) {
      if (!is_string ($Address) || (strlen ($Address) != 6))
        return false;
      
      $this->etherSrc = $Address;
      
      return true;
    }
    // }}}
    
    // {{{ getDestinationAddress
    /**
     * Retrive the destination-address of this ethernet-frame
     * 
     * @param bool $Human (optional)
     * 
     * @access public
     * @return string
     **/
    public function getDestinationAddress ($Human = false) {
      return ($Human ? $this::getReadableMAC ($this->etherDst) : $this->etherDst);
    }
    // }}}
    
    // {{{ getProtocolNumber
    /**
     * Retrive the number of this layer-3 protocol on this frame
     * 
     * @access public
     * @return int
     **/
    public function getProtocolNumber () {
      return $this->etherProtoType;
    }
    // }}}
    
    // {{{ outputDebug
    /**
     * Output Debug-Information about this ethernet-frame
     * 
     * @access public
     * @return void
     **/
    public function outputDebug () {
      static $frameTypeMap = array (
        self::ETHER_FRAME_V2 => 'etherframe V2',
        self::ETHER_FRAME_802 => 'etherframe 802.3, DSAP 0x%2$02X, SSAP 0x%3$02X, Ctrl 0x%4$02X',
        self::ETHER_FRAME_802_RAW => 'etherframe 802.3r/IPX',
        self::ETHER_FRAME_802_SNAP => 'etherframe 802.3s, OUID %1$04X',
      );
      
      printf (
        '%s > %s %s%s, ethertype %s (0x%04X), length %d, payload length %d' . "\n",
        $this->getSourceAddress (true), $this->getDestinationAddress (true),
        sprintf ($frameTypeMap [$this->etherFrameType], $this->etherOUID, $this->ether802DSAP, $this->ether802SSAP, $this->ether802Control),
        ($this->vlanID !== null ? sprintf (', VLAN %s (Priority %d)', $this->vlanID, $this->vlanPriority) : ''),
        (isset (self::$Protocols [$this->etherProtoType]) ? self::$Protocols [$this->etherProtoType][0] : 'Unknown'),
        $this->etherProtoType,
        $this->etherLength,
        strlen (is_object ($this->etherPayload) ? $this->etherPayload->dump () : $this->etherPayload)
      );
      
      // Inherit to payload
      if (is_object ($this->etherPayload))
        $this->etherPayload->outputDebug ();
      # elseif (is_string ($this->etherPayload) && function_exists ('dump'))
      #  dump ($this->etherPayload);
    }
    // }}}
    
    // {{{ process
    /**
     * Process this frame and return a response-frame (if a response is needed)
     * 
     * @access public
     * @return Ethernet_Frame
     **/
    public function process () {
      // Check if we may process this frame
      if (!is_object ($this->etherPayload))
        return;
      
      // Try to process this frame
      if (!is_object ($Response = $this->etherPayload->process ()))
        return $Response;
      
      // Create a response-frame and switch sender and receiver
      $Frame = clone $this;
      
      $Frame->etherDst = $this->etherSrc;
      $Frame->etherSrc = $this->etherDst;
      
      // Encapsulate the response
      $Frame->etherProtoType = $Response::PROTOCOL_NUMBER;
      $Frame->etherPayload = $Response;
      $Frame->etherLength = null;
      
      // Return the encapsulated resonse
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
      // Start output with ethernet-addresses
      $Output = $this->etherDst . $this->etherSrc;
      
      // Append VLAN-Information (if there is one)
      if ($this->vlanID !== null)
        $Output .=
          "\x81\x00" .
          chr ((($this->vlanPriority & 0x0E) << 5) | ($this->vlanCanonical ? 0x10 : 0x00) | (($this->vlanID >> 8) & 0x0F)) .
          chr ($this->vlanID & 0xFF);
      
      // Prepare the payload
      if (is_object ($this->etherPayload))
        $Payload = $this->etherPayload->dump ();
      else
        $Payload = $this->etherPayload;
      
      // Output information about payload
      if ($this->etherFrameType == $this::ETHER_FRAME_V2)
        $Output .= chr (($this->etherProtoType >> 8) & 0xFF) . chr ($this->etherProtoType & 0xFF);
      else {
        // Append total length of frame to output
        $Length = strlen ($Payload) + strlen ($Output);
        $Output .= chr (($Length >> 8) & 0xFF) . chr ($Length & 0xFF);
        
        if ($this->etherFrameType == $this::ETHER_FRAME_802_RAW)
          $Output .= "\xFF\xFF";
        elseif ($this->etherFrameType == $this::ETHER_FRAME_802_SNAP)
          $Output .=
            "\xAA\xAA\x03" .
            chr (($this->etherOUID >> 16) & 0xFF) .
            chr (($this->etherOUID >> 8) & 0xFF) .
            chr ($this->etherOUID & 0xFF) .
            chr (($this->etherProtoType >> 8) & 0xFF) .
            chr ($this->etherProtoType & 0xFF);
        else
          $Output .= chr ($this->ether802DSAP) . chr ($this->ether802SSAP) . chr ($this->ether802Control);
      }
      
      // Append the payload
      $Output .= $Payload;
      
      $this->etherLength = strlen ($Output);
      
      return $Output;
    }
    // }}}
  }
  
  interface Ethernet_Protocol {
    public function parse ($Data);
    public function process ();
    public function dump ();
    public function outputDebug ();
  }

?>