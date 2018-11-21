require 'thor'

# Runner
class Runner
  include Thor::Base

  def self.batch(&block)
    runner = Runner.new
    runner.instance_eval(&block)
    runner.execute
  end

  def initialize(config = {}, &block)
    @config = config
    instance_eval(&block) if block_given?
  end

  def scripts
    @scripts ||= []
  end

  def run(command, config = {})
    say_status :run, command, config.fetch(:verbose, true)
    scripts << command
  end

  def execute
    command = scripts.join(' && ')
    return if @config[:'dry-run']
    @config[:capture] ? `#{command}` : system(command)
  end
end