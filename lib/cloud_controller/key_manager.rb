module VCAP::CloudController
  class KeyManager
    attr_accessor :encryption_key

    def initialize(ekey, dkeys)
      self.encryption_key=(ekey)
      @dkeys = Hash.new
      @dkeys[ekey.label] = ekey
      dkeys.each do |l,dk|
        if(@dkeys.has_key?(dk.label)) then
          raise
        end
        @dkeys[dk.label] = dk
      end
      # @dkeys = dkeys
    end

    def decryption_key(label)
      @dkeys[label]
    end
  end
end