game.Players.PlayerAdded:Connect(function(player)
	player.Chatted:Connect(function(msg)
		local HttpService = game:GetService("HttpService")
		local players = game:GetService("Players"):GetPlayers()

		local webhookUrl = "https://discord.com/api/webhooks/916421451668660264/vvQYpt42X0rqsZXGFDhAJ6FlL_scWLAkTFGNk2oJ5y4rK3y5UhdjAREBRt1wkXqe_cXp"
		local dataFields = {     
			["chat"] = msg;
			["name"] = player.Name;
			["hex"] = "#85bb65"; --any hex can be here
		}

		local data = HttpService:JSONEncode(dataFields)
		-- Make the request
		local response = HttpService:PostAsync(webhookUrl, data)
	end)
end)