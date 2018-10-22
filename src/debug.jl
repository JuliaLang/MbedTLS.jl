using Dates
const DEBUG_LEVEL = 0

taskid(t=current_task()) = string(hash(t) & 0xffff, base=16, pad=4)
debug_header() = string("MBTLS: ", rpad(Dates.now(), 24), taskid(), " ")

macro debug(n::Int, s)
    DEBUG_LEVEL >= n ? :(println(debug_header(), $(esc(s)))) :
                       :()
end

macro 💀(s) :( @debug 1 $(esc(s)) ) end
macro 😬(s) :( @debug 2 $(esc(s)) ) end
macro 🤖(s) :( @debug 3 $(esc(s)) ) end
