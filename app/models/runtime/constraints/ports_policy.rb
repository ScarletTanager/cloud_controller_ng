class PortsPolicy
  def initialize(app)
    @app = app
    @errors = app.errors
  end

  def validate
    return if @app.ports.nil? || @app.ports.empty?
    return @errors.add(:ports, 'Custom app ports supported for Diego only. Enable Diego for the app or remove custom app ports.') if !@app.diego
    return @errors.add(:ports, 'Maximum of 10 app ports allowed.') if ports_limit_exceeded?
    return @errors.add(:ports, 'must be integers') unless all_ports_are_integers?
    @errors.add(:ports, 'Ports must be in the 1024-65535.') unless all_ports_are_in_range?
  end

  private

  def all_ports_are_integers?
    @app.ports.all? { |port| port.is_a? Integer }
  end

  def all_ports_are_in_range?
    @app.ports.all? do |port|
      port > 1023 && port <= 65535
    end
  end

  def ports_limit_exceeded?
    @app.ports.length > 10
  end
end
