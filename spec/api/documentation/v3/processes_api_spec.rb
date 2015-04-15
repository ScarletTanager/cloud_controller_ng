require 'spec_helper'
require 'awesome_print'
require 'rspec_api_documentation/dsl'

resource 'Processes (Experimental)', type: :api do
  let(:iso8601) { /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.freeze }
  let(:user) { VCAP::CloudController::User.make }
  let(:user_header) { headers_for(user)['HTTP_AUTHORIZATION'] }
  header 'AUTHORIZATION', :user_header

  def do_request_with_error_handling
    do_request
    if response_status == 500
      error = JSON.parse(response_body)
      ap error
      raise error['description']
    end
  end

  get '/v3/processes' do
    parameter :page, 'Page to display', valid_values: '>= 1'
    parameter :per_page, 'Number of results per page', valid_values: '1-5000'

    let(:name1) { 'my_process1' }
    let(:name2) { 'my_process2' }
    let(:name3) { 'my_process3' }
    let(:app_model) { VCAP::CloudController::AppModel.make(space_guid: space.guid) }
    let!(:process1) { VCAP::CloudController::ProcessFactory.make(name: name1, space: space, app_guid: app_model.guid) }
    let!(:process2) { VCAP::CloudController::ProcessFactory.make(name: name2, space: space) }
    let!(:process3) { VCAP::CloudController::ProcessFactory.make(name: name3, space: space) }
    let!(:process4) { VCAP::CloudController::ProcessFactory.make(space: VCAP::CloudController::Space.make) }
    let(:space) { VCAP::CloudController::Space.make }
    let(:page) { 1 }
    let(:per_page) { 2 }

    before do
      space.organization.add_user user
      space.add_developer user
    end

    example 'List all Processes' do
      expected_response = {
        'pagination' => {
          'total_results' => 3,
          'first'         => { 'href' => '/v3/processes?page=1&per_page=2' },
          'last'          => { 'href' => '/v3/processes?page=2&per_page=2' },
          'next'          => { 'href' => '/v3/processes?page=2&per_page=2' },
          'previous'      => nil,
        },
        'resources'  => [
          {
            'guid'       => process1.guid,
            'type'       => process1.type,
            'command'    => nil,
            'created_at' => iso8601,
            'updated_at' => iso8601,
            '_links'     => {
              'self'     => { 'href' => "/v3/processes/#{process1.guid}" },
              'app'      => { 'href' => "/v3/apps/#{app_model.guid}" },
              'space'    => { 'href' => "/v2/spaces/#{process1.space_guid}" },
            },
          },
          {
            'guid'       => process2.guid,
            'type'       => process2.type,
            'command'    => nil,
            'created_at' => iso8601,
            'updated_at' => iso8601,
            '_links'     => {
              'self'     => { 'href' => "/v3/processes/#{process2.guid}" },
              'app'      => { 'href' => "/v3/apps/#{process2.app_guid}" },
              'space'    => { 'href' => "/v2/spaces/#{process2.space_guid}" },
            },
          }
        ]
      }

      do_request_with_error_handling

      parsed_response = MultiJson.load(response_body)
      expect(response_status).to eq(200)
      expect(parsed_response).to be_a_response_like(expected_response)
    end
  end

  get '/v3/processes/:guid' do
    let(:process) { VCAP::CloudController::ProcessFactory.make }
    let(:guid) { process.guid }
    let(:type) { process.type }

    before do
      process.space.organization.add_user user
      process.space.add_developer user
    end

    example 'Get a Process' do
      expected_response = {
        'guid'       => guid,
        'type'       => type,
        'command'    => nil,
        'created_at' => iso8601,
        'updated_at' => iso8601,
        '_links'     => {
          'self'     => { 'href' => "/v3/processes/#{process.guid}" },
          'app'      => { 'href' => "/v3/apps/#{process.app_guid}" },
          'space'    => { 'href' => "/v2/spaces/#{process.space_guid}" },
        },
      }

      do_request_with_error_handling
      parsed_response = MultiJson.load(response_body)

      expect(response_status).to eq(200)
      expect(parsed_response).to be_a_response_like(expected_response)
    end
  end

  patch '/v3/processes/:guid' do
    let(:buildpack_model) { VCAP::CloudController::Buildpack.make(name: 'another-buildpack') }
    let(:process) { VCAP::CloudController::AppFactory.make }

    before do
      process.space.organization.add_user user
      process.space.add_developer user
    end

    parameter :memory, 'Amount of memory (MB) allocated to each instance'
    parameter :instances, 'Number of instances'
    parameter :disk_quota, 'Amount of disk space (MB) allocated to each instance'
    parameter :space_guid, 'Guid of associated Space'
    parameter :stack_guid, 'Guid of associated Stack'
    parameter :state, 'Desired state of process'
    parameter :command, 'Start command for process'
    parameter :buildpack, 'Buildpack used to stage process'
    parameter :health_check_timeout, 'Health check timeout for process'
    parameter :docker_image, 'Name of docker image containing process'
    parameter :environment_json, 'JSON key-value pairs for ENV variables'
    parameter :type, 'Type of the process'

    let(:memory) { 2555 }
    let(:instances) { 2 }
    let(:disk_quota) { 2048 }
    let(:space_guid) { process.space.guid }
    let(:stack_guid) { process.stack.guid }
    let(:command) { 'X' }
    let(:state) { 'STARTED' }
    let(:buildpack) { buildpack_model.name }
    let(:health_check_timeout) { 70 }
    let(:environment_json) { { 'foo' => 'bar' } }
    let(:type) { 'worker' }

    let(:guid) { process.guid }

    let(:raw_post) { MultiJson.dump(params, pretty: true) }

    example 'Updating a Process' do
      expect {
        do_request_with_error_handling
      }.to change { VCAP::CloudController::Event.count }.by(1)
      process.reload

      expected_response = {
        'guid'       => guid,
        'type'       => type,
        'command'    => 'X',
        'created_at' => iso8601,
        'updated_at' => iso8601,
        '_links'     => {
          'self'     => { 'href' => "/v3/processes/#{process.guid}" },
          'app'      => { 'href' => "/v3/apps/#{process.app_guid}" },
          'space'    => { 'href' => "/v2/spaces/#{process.space_guid}" },
        },
      }

      parsed_response = JSON.parse(response_body)
      expect(response_status).to eq(200)
      expect(parsed_response).to be_a_response_like(expected_response)

      expect(process.state).to eq(state)
      expect(process.command).to eq(command)
      expect(process.memory).to eq(memory)
      expect(process.instances).to eq(instances)
      expect(process.disk_quota).to eq(disk_quota)
      expect(process.buildpack).to eq(buildpack_model)
      expect(process.health_check_timeout).to eq(health_check_timeout)
      expect(process.environment_json).to eq(environment_json)
      expect(process.type).to eq(type)
    end
  end
end
