spinel_proto = Proto("Spinel", "Spinel protocol")

function spinel_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "SPINEL"
    pinfo.cols.src = 'Host'
    pinfo.cols.dst = 'NCP'  

    local subtree = tree:add(spinel_proto,buffer(),"Spinel Protocol Data")
    subtree:add(buffer(0,2),"The first two bytes: " .. buffer(0,2):uint())
    subtree = subtree:add(buffer(2,2),"The next two bytes")
    subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end

function dump(o)
    if type(o) == 'table' then
       local s = '{ '
       for k,v in pairs(o) do
          if type(k) ~= 'number' then k = '"'..k..'"' end
          s = s .. '['..k..'] = ' .. dump(v) .. ','
       end
       return s .. '} '
    else
       return tostring(o)
    end
 end


wtap_table = DissectorTable.get("wtap_encap")
wtap_table:add(wtap.USER0, spinel_proto)

print("table: ", dump(wtap_table))