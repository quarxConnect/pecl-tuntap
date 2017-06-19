<?PHP

  class TAP_Frame extends Ethernet_Frame {
    /* Flags for this TAP-Frame (Unknown) */
    public $tapFlags = 0x0000;
    
    /* Protocol transported on ethernet-frame of this TAP-Frame */
    public $tapProto = 0x0000;
    
    // {{{ parse
    /**
     * Parse data from payload into this object
     * 
     * @param string $Data
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data) {
      // Check minimum length
      if (strlen ($Data) < 4) {
        trigger_error ('TAP-Frame too short');
        
        return false;
      }
      
      // Parse TAP-Header
      $tapFlags = (ord ($Data [0]) << 8) | ord ($Data [1]);
      $tapProto = (ord ($Data [2]) << 8) | ord ($Data [3]);
      
      // Try to parse the ethernet-frame on payload
      if (!parent::parse (substr ($Data, 4))) {
        trigger_error ('Failed to parse Ethernet-Frame');
        
        return false;
      }
      
      // Sanity-Check
      if ($tapProto != $this->getProtocolNumber ())
        trigger_error ('Protocols from TAP-Frame and Ethernet-Frame do not match: ' . $tapProto . ' / ' . $this->getProtocolNumber ());
      
      // Copy TAP-Data to this object
      $this->tapFlags = $tapFlags;
      $this->tapProto = $tapProto;
      
      return true;
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
      // Try to dump at ethernet-level
      if (($Output = parent::dump ()) === false)
        return $Output;
      
      // Retrive the protocol-number on output
      $Proto = $this->getProtocolNumber ();
      
      // Prepend TAP-Header
      return "\x00\x00" . chr (($Proto >> 8) & 0xFF) . chr ($Proto & 0xFF) . $Output;
    }
    // }}}
    
    // {{{ outputDebug
    /**
     * Output debug-info about this frame
     * 
     * @access public
     * @return void
     **/
    public function outputDebug () {
      // Output debug-info about ourself
      printf ('TAP 0x%04X ', $this->tapFlags);
      
      // Inherit to our parent
      parent::outputDebug ();
    }
    // }}}
  }

?>